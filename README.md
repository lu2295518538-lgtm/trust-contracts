# contracts/ — 链上合约源码镜像

本目录是 VM `/home/ljh/my-contract/`（git 裸仓）的只读镜像，2026-09-22 由系统审视 P0-1 建立。
**权威源在 VM 裸仓**；本目录用于本地审阅与主仓备份，修改合约请先改 VM 侧并走部署流程。

## 链上部署全景（chain1，2026-09-22 实测 `cmc query contract list`）

链上共 36 个合约 = 17 个系统合约 + 19 个用户 DOCKER_GO/WASM 合约。

### 当前在用（6 个，代码实际调用）

| 合约名 | 版本 | 源码位置 | 调用方 | 用途 |
|---|---|---|---|---|
| access_control_v2 | 1.0.0 | `access_control.go`（含 safeKey 补丁，三方 md5 dc74c2ca 一致） | core/chain_policy.py | 任务二 ABAC 链上终判 |
| standard_manager | 1.0.0 | `standard_manager/` | core/quality.py | 任务三质量标准多版本管理 |
| data_certify | 1.0.1 | `data_certify/` | core/quality.py | 任务三认证/预警追加式存证 |
| attr_query_v3 | 1.0.0 | **`attr_query_v2/`（同一份源码，见下）** | core/chainmaker_client.py L21 `ATTR_QUERY_V3_CONTRACT` | 任务四 M1 多属性哈希实体匹配 |
| trace_rw | 2.0 | `trace_rw/` | app.py /api/trace/deps | 任务四 M3 读写依赖边存证 |
| fact | 1.0 (WASM) | 无 Go 源码（WASM 二进制 fact.wasm，链自带示例合约改造） | core/chainmaker_client.py store_on_chain | 任务一确权存证 + 日志 Merkle 锚定 |

### attr_query_v3 源码说明（2026-09-22 破案）

- 链上 `attr_query_v3` 的构建源码就是 `attr_query_v2/main.go`（800 行，含 tokensOf/getEntityByKey/queryAllEntitiesPage）。
- 证据：attr_query_v3.7z 内编译产物时间戳（2026-09-02 22:00:40）与 attr_query_v2/main.go 修改时间一致；二进制内符号 `main.tokensOf` 与源码匹配；deploy_v3.sh 显示由该 7z 部署。
- v3 只是**换名重新部署**（合约无删除方法，v2 链上脏数据无法修补），源码与 v2 相同。
- 历史版本 attr_query（v1）、attr_query_v2 仍在链上但已不被代码调用。

### 历史/实验合约（链上 12 个，零代码引用，2026-09-22 已验证）

exp0、exp_v3~exp_v8、dc_test、sm_orig、smcopy、access_control(v1)、attr_query(v1)、attr_query_v2
- VM 运行目录与本地仓库 grep 均为零调用引用（仅注释/测试说明提及）。
- 长安链合约不可删除，保留在链上不影响任何功能；答辩口径：「在用 6 个 + 版本演进/实验残留 12 个，演进历史本身即链上不可篡改的研发过程证据」。
- 文件系统侧实验产物已归档至 VM `my-contract/archive/` 与本目录 `archive/`（smcopy）。

## 构建纪律（血泪，勿破）

- 三件套缺一不可：`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w"`。
- 动态链接二进制会永久毒化 vm-engine 合约缓存（GLIBC 不兼容 → INIT 超时）。
- VM 无外网：新合约复用已有目录的 go.mod/go.sum，禁止 `go mod tidy`。
- 部署 .7z 内只放 contract_name 一个条目（编译产物），无 Dockerfile。
- Go 位于 `/usr/local/go/bin/go`（不在非交互 shell PATH）。
