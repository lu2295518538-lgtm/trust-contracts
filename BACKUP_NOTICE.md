# 合约源码备份说明（BACKUP_NOTICE）

本仓库（VM `/home/ljh/my-contract`）是长安链合约源码的**构建权威源**。
本机不出网，无法直接 push 到 GitHub，远程备份经宿主中转完成。

## 备份位置
- GitHub 私有仓：`lu2295518538-lgtm/trust-contracts`（main 分支）
- 本地镜像：`trust_contracts_repo/`（独立仓，origin 指向上述 GitHub）
- 主仓镜像：`trust_verification_repo/contracts/`（随主仓版本管理）

## 同步机制
宿主侧执行（需 SSH_PASS 环境变量）：
```bash
# VM → 本地主仓 contracts/
SSH_PASS=xxxx python tools/sync_contracts.py
# VM → 本地独立合约仓
SSH_PASS=xxxx python tools/sync_contracts.py --contracts-dir <trust_contracts_repo路径>
# 同步 + commit + push GitHub（独立仓才有 origin）
SSH_PASS=xxxx python tools/sync_contracts.py --contracts-dir <trust_contracts_repo路径> --push
```

## 链上全景（契约）
- 在用 6：access_control_v2 / standard_manager / data_certify / attr_query_v3(v2 源码) / trace_rw / fact(WASM)
- 实验/历史 12：链上保留（合约不可删除），源码归档至 archive/
- attr_query_v3 = attr_query_v2/main.go 构建（deploy_v3.sh 证实），勿删除 v2 源码