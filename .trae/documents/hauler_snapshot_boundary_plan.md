# Hauler Store 快照边界（Snapshot Boundary）实现计划

## 一、仓库调研结论

### 当前架构

- Store 是磁盘上的 OCI layout：`index.json`（全量描述符目录，唯一"目录"）+ `blobs/sha256/<hex>`（内容寻址、不可变）+ `store.json`。
- `pkg/content/oci.go`：
  - blob 写入已经是"临时文件 + 校验 digest + rename"，失败不碰最终路径（`WriteBlob`/`ociBlobWriter`）；
  - `index.json` 也是整文件 temp + rename，并做 fsync 合并（`indexCheckpointInterval`）；
  - 进程内用 `o.mu` 保护 nameMap，`Walk` 在锁内生成快照后释放；`Fetch` 无锁、直接打开 blob 文件。
- `pkg/store/store.go`：
  - `AddImage` 把**基础镜像与每个 sig/att/sbom/referrer 分成多次 `AddIndex` 逐次落盘**（writeImage/writeIndex 末尾各保存一次 index）；
  - `AddArtifactCollection`、load（经 `ociPusher.Push`）同样逐条发布；
  - `RemoveArtifact` = LoadIndex + 从内存 nameMap 删除 + SaveIndex（两段独立临界区）；`RemoveCmd` 逐个 artifact 保存后再 `CleanUp`；
  - `CleanUp` 直接 `os.Remove` 未被引用的 blob 文件，**不等待任何在途读取**；`Flush` 顺序 RemoveAll。
- `cmd/hauler/cli/store/serve.go`：启动临时 registry，经 HTTP 把 store 全量 copy 进 registry 根目录（distribution 自己的 `blobs/aa/<hex>/data` + `repositories/.../link` 结构），再启动正式 registry。**建账 copy 期间没有任何读快照保护**；建账完成后 registry 读独立目录，不再访问 store。
- `pkg/store/inventory.go`：stores.json 有 flock 保护，但临时文件是固定名 `stores.json.tmp`；store.json 同样用固定 `.tmp`。
- 临时对象命名点分散：`index-*.json`（store 根）、`<hex>.tmp-*`（blobs 目录）、`stores.json.tmp`、`store.json.tmp`、`.<base>.hauler-extract-`（fileserver/git 解包）。
- 跨进程：index.json 的读-改-写**没有文件锁**，两个 hauler 进程并发改 store 时后写覆盖先写（store.json/stores.json 除外，它们各有 flock）。依赖已有 `github.com/gofrs/flock v0.13.1`（支持共享锁 RLock）。

### 一致性缺口（对应需求）

1. **半发布**：一次 AddImage/load 期间，index.json 多次对外可见，读者可能看到"基础镜像已在、referrer 未齐"；中途失败（digest 不符、referrer 拉取失败）留下已发布的局部结果。
2. **删除竞态**：Walk/Resolve 拿到快照后、Fetch 打开 blob 前，另一路径的 `CleanUp`/`Flush` 可把 blob unlink → 同一次逻辑读里 manifest 存在但 blob 404；serve 建账 copy 撞上并发 remove/GC 会把残缺内容推进 registry，客户端随后拉到互相矛盾的 manifest/blob/referrer。
3. **跨进程丢更新**：无 index.json 事务锁。
4. **崩溃残留**：残留临时对象从不在启动时清扫（CleanUp 顺带删 blob 目录里的非摘要名文件，但根目录 `index-*.json`、inventory `.tmp`、解包 staging 永不清理），且命名不统一、无法被各组件识别。
5. **无可观察的版本身份**：读者无法说明自己读的是哪一版，恢复后也无法核对。

## 二、设计：统一的快照边界

**快照定义：一代 `index.json`（带 generation 注解）+ 它引用的全部不可变 blob 文件。**

`index.json` 的一次原子 rename 就是唯一的发布点；blob 永不被原地改写（新增安全，删除受独占边界保护）。在此定义上提供三类原语，serve、layout、inventory、校验、删除、恢复全部接入：

1. **View（读快照租约）**：一次逻辑读（Walk 快照 + 其后全部 Fetch/外发推送）开始时获取，携带 generation；进程内 `sync.RWMutex` 读锁 + store 根内 flock 共享锁（`<root>/.hauler/snapshot.lock`）。
   - 旧 View 读旧版：其需要的 blob 在租约释放前不会被删（GC 持独占锁等待）→ **旧请求可完成**；
   - commit 只做 index 原子切换、不删 blob，故新增不阻塞 View；View 结束后新请求拿到的是新一代 → **新请求只看完整版本**。
2. **Tx（原子更新事务）**：事务期间写 blob（内容寻址、未被索引即不可见），所有 index 变更进内存缓冲；Commit 时：释放共享锁→获取**独占 flock**（带超时）→ 从盘上重读 index.json 与缓冲合并 → **提交前校验**（缓冲内每个 manifest/index 可达的 config、layers、child manifests 的 blob 均存在且 size 相符）→ 一次 `saveIndexLocked(true)` 落盘并 `generation++`。任何步骤失败：缓冲丢弃、index.json 不动 → **失败更新不半发布**；未落索引的 blob 不可见，由后续 CleanUp 回收。
3. **Exclusive（删除/清空边界）**：CleanUp/Flush/批量 remove 获取独占 flock + 进程内写锁（带超时，超时返回类型化错误），"index 一次提交 + blob unlink"在同一独占区间内完成，从库外看只有"旧版/新版"两个状态。

**恢复（重启）**：`NewLayout` 打开 store 时尝试**短时独占锁**：获得即证明当前没有其他存活 hauler 进程持租约，按统一 pattern 清扫全部残留临时对象（index temp、blob temp、staging 目录、store.json temp），返回 `SweepResult{Removed, Skipped}` 并记日志；得不到锁（其他进程活跃）则跳过清扫、正常打开。inventory 在已有的 flock 临界区内清扫自身残留 temp。临时文件全部改为**唯一名 + 统一可识别后缀/前缀**。

**跨进程退化策略**：flock 获取失败/超时时，进程内 gate 仍保证单进程一致性；跨进程记录明确警告并返回可观察的类型化错误（命令可重试），与现有 storeID/inventory 锁的 best-effort 风格一致；容忍 NFS 上的 ENOTSUP/EINVAL。

### 可观察结果

- `index.json` 顶层注解：`hauler.dev/snapshot-generation`（uint64 单调递增）、`hauler.dev/snapshot-time`（RFC3339 UTC）。
- `Layout.SnapshotInfo()`：当前 generation、提交时间、artifact 数；`store info --json` 增加 `snapshot-generation` 字段，文本模式日志输出版本。
- `Layout.LastSweep()`：本次启动清扫结果（删除数/跳过数）。
- 类型化错误：`ErrSnapshotValidation`（提交校验失败）、`ErrSnapshotLockBusy`（独占等待超时）。
- View 暴露 `Generation()`，调用方可在日志/错误中注明所读版本。

## 三、修改的文件与模块

- `pkg/consts/consts.go`：generation 注解键、锁文件相对路径 `.hauler/snapshot.lock`、统一临时 pattern 常量（index temp 后缀 `.json.tmp`、blob temp 段 `.tmp-`、staging 前缀 `.hauler-staging-` 等）、锁超时常量（View 短、Exclusive 长）。
- `pkg/content/snapshot.go`（**新**）：`snapshotLock`（gofrs flock 共享/独占 + 超时、进程内 RWMutex gate、ENOTSUP 容忍）、`SweepTemp(root) SweepResult`、pattern 判定、`SweepResult`/类型化错误。
- `pkg/content/oci.go`：
  - OCI 持有 snapshotLock 与 `generation uint64`；
  - 新 API：`View(ctx) (*View, error)`、`BeginTx(ctx) (*Tx, error)`（`Tx.AddIndex/Tx.RemoveIndex/Commit/Rollback`、`Tx.Target() Target` 供本地 CopyAll 缓冲）、`Exclusive(ctx, fn) error`、`SweepTemp`、`SnapshotGeneration()`；
  - loadIndexLocked 读 generation；所有 index 落盘统一走"一次 bump generation"的提交路径，checkpoint/fsync 合并逻辑保留；
  - 新增 `validateCommitted`：沿缓冲描述符的 manifest/index JSON 递归校验 blob 存在性与 size；
  - `AddIndex/RemoveFromIndex/SaveIndex/UpdateAnnotations` 保留为"单操作自动提交事务"包装（兼容现有调用与测试）；`ociPusher.Push` 的 index 写入支持绑定 Tx（load/CopyAll 整包一次提交）；
  - index temp 改名为 `index-*.json.tmp`。
- `pkg/store/store.go`：
  - `NewLayout` 调用 SweepTemp 并保存结果；新增 `Layout.Update(ctx, fn) (gen, err)`、`View`、`SnapshotInfo()`、`LastSweep()`；
  - `AddArtifact`、**`AddImage`（基础镜像 + 全部 sig/att/sbom/referrer 合一事务）**、`writeImage/writeIndex/saveReferrers/saveRelatedArtifacts` 改为事务内缓冲发布（签名增加 tx appender 参数）；
  - `AddArtifactCollection` 整批一个事务；
  - `RemoveArtifact`→新增 `RemoveArtifacts`（批量缓冲、一次提交），并在同一独占区间内执行 GC；`CleanUp`/`Flush` 走 Exclusive，Flush 同时清扫 temp；
  - `CopyAll` 在源端 View 租约内完成。
- `pkg/store/inventory.go`：temp 改唯一名 `stores-*.json.tmp`，锁内清扫残留；`store.json` 临时名同样改唯一（store.go 的 loadOrCreateStoreID）。
- `cmd/hauler/cli/store/serve.go`：registry 建账 `CopyCmd` **整体包一个 View**（拿不到锁时重试/返回 ErrSnapshotLockBusy）；fileserver/git 启动时按统一 pattern 清扫 RootDir 的解包残留。
- `cmd/hauler/cli/store/copy.go`：registry/dir 两个 Walk 分支整体包一个 View（建账与 file/git 导出期间不受 GC 干扰）。
- `cmd/hauler/cli/store/remove.go`：匹配收集后调用一次 `RemoveArtifacts`（含 GC），审计日志按条目保留。
- `cmd/hauler/cli/store/load.go`：解出的临时 layout 经目标端 Tx 提交，**整个 haul 一代可见**，失败整包不可见。
- `cmd/hauler/cli/store/info.go`：JSON 输出 generation；`--check` 与外层 View 不嵌套（Checker 自持租约或复用传入租约，二选一，避免同 goroutine 重入 RLock）。
- `internal/mapper/unpack.go`：staging 前缀常量移到 consts 与其他 pattern 并列（现有 `.hauler-extract-` 前缀不变）。
- `internal/server/registry.go`：无需改动（租约在 cmd 层持有；distribution 自身的 `_uploads` 不由 hauler 管理，readonly 服务不产生上传）。

## 四、实现步骤（依赖顺序）

1. consts：注解键、锁路径、临时 pattern、超时常量。
2. `pkg/content/snapshot.go`：锁/gate/清扫原语 + 单测（锁互斥、共享并发、超时、pattern 匹配、清扫、持锁时跳过）。
3. `pkg/content/oci.go`：generation 读写、Tx/View/Exclusive/Sweep API、validateCommitted；旧 API 改为薄包装；ociPusher 绑定 Tx；temp 改名。
4. content 层测试：并发 View+Commit、跨句柄（模拟跨进程）GC 等待、generation 单调、校验失败回滚。
5. `pkg/store/store.go`：NewLayout 清扫接入；Update/View/SnapshotInfo；Add 系列改造为单事务；RemoveArtifacts/CleanUp/Flush 独占化。
6. `pkg/store/inventory.go` + store.json temp：唯一名与清扫。
7. cmd 层接入：copy.go、serve.go、remove.go、load.go、info.go；unpack 常量归位。
8. 端到端测试（见下），全量回归并修正受语义变化影响的既有测试。

## 五、验证（新增测试覆盖需求点）

- **并发读写**：长 View 的 Walk+Fetch 进行中并发多 Tx 提交；View 内只见起始 generation 且全部 blob 可读；View 释放后新 View 看到新版本；generation 严格单调。
- **删除竞态**：View 持有期间（fetch 注入延时）并发 `RemoveArtifacts`+GC，断言 GC 阻塞到 View 释放、View 内每个 manifest 的 config/layers 全部 200；释放后 manifest 404。用两个独立 OCI 句柄验证 flock 跨句柄互斥（模拟跨进程）。
- **校验失败**：直接构造引用缺失 blob 的 Tx，Commit 返回 `ErrSnapshotValidation`，index.json 字节不变、generation 不变；digest-mismatch 的层写入不落最终路径（已有测试）继续通过。
- **失败更新不半发布**：AddImage 在 referrer 拉取阶段注入失败 → 基础镜像与 extras 均不可见、generation 不变、无残留 temp；重试成功后 manifest/blob/referrer 同代可见。
- **恢复可观察**：手工植入各类残留 temp（index/blob/staging/inventory），重新 `NewLayout`（独占可获得）后全部清除、Walk 不含任何临时对象、index.json 可解析、generation 跨重开稳定；另一持共享锁句柄存在时清扫返回 Skipped 且 store 正常打开。
- **serve 建账一致性**：建账 copy 进行中并发 remove+GC（GC 被租约阻塞），建账完成后对 catalog 中每个 manifest 整图拉取（manifest→config/layers、index→child、referrer→subject 相关集合）无 404，GC 在建账后才执行。
- **inventory 并发**：多句柄并发 `updateStoreInventory` 不丢条目，无 temp 残留。
- 命令行：`go build ./...`、`go vet ./...`、`go test ./pkg/content/... ./pkg/store/... ./internal/... ./cmd/hauler/cli/store/...`（后者多为 httptest 本地 registry，无需外网；需要 Docker 守护进程的用例按现有约束跳过）。

## 六、风险与处理

- **语义变化：AddImage 拉取 extras 失败时，基础镜像也不再保留**（当前 RelatedArtifactError 会保留镜像）。这是"失败更新不半发布、manifest 与 referrer 同代可见"的直接要求；需同步更新相关测试断言与错误文案（错误中说明整次添加已回滚、可重试）。
- **长 View 阻塞删除**：独占等待有超时上限，超时返回 `ErrSnapshotLockBusy`（命令可重试、信息可观察），避免 remove 无限挂起。
- **flock 在 NFS/共享盘上的兼容性**：沿用现有 best-effort 模式（超时、警告、ENOTSUP/EINVAL 容忍）；文件锁不可用时进程内 gate 仍生效。
- **load 整包原子化**：一个 haul 内多构件改为同代提交，中途失败整包不可见（当前是逐个可见），符合需求；代价是失败时需重跑整个 load（现状本就要求重跑）。
- **性能**：AddImage 由 N 次 index 落盘减为 1 次（正向）；每次逻辑读多一次 flock 系统调用；CleanUp 因等待在途 View 而延后 unlink，行为正确化。
- **公共 API 兼容**：保留 AddIndex/SaveIndex/RemoveFromIndex 等方法签名（语义变为单操作事务），降低对现有 100+ 测试与外部调用的冲击。
- **serve 之后的 store 变更**仍需重启 serve 才生效（既有冻结复制架构，本次不改）；本次保证的是建账读取与 store 自身所有读写路径共享同一边界。
