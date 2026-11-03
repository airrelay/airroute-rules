# 发布与回退

`main` 保存 Python、配置、测试和文档；**同一仓库**的 `release` 分支仅保存公开产物。不存在常驻控制器、节点、Globalping、数据库或 GitHub Releases 发布服务。工作流每日 03:17 UTC 或手动运行，手动可关闭发布以只生成候选。

## 一致版本

发布分支布局：

```text
current.json
README.md
versions/<data_version>/manifest.json
versions/<data_version>/geo.ardb
versions/<data_version>/asn.ardb
versions/<data_version>/.../*.list
versions/<data_version>/...报告及注册表
```

消费者先读取 `current.json` 一次，再根据其中的 `manifest` 路径读取不可变目录；核验 manifest SHA-256，再核验每个文件的长度和摘要。`.list`、Geo、ASN、注册表和来源版本均属于同一 manifest。不要在多个请求中反复读取可变入口后拼装文件。

完整候选和入口在**同一个 Git commit**中更新，并以普通非 force push 提交；多文件在 Git 树上原子生效。构建、验证、远端拒绝或网络故障不会半更新入口。不删除旧版本目录，因此客户端已读取旧入口时仍可完成下载，回退也不必重建旧产物。

版本号由数据和配置决定，不由工作流时间或源码中无关的文档变化决定。版本目录禁止原地改写；相同版本的 manifest 不一致即失败。入口已经指向相同 manifest 时不创建提交。

## 并发、异常和恢复

Actions 的仓库级并发组禁止两个工作流同时发布。发布前重新核对远端 `main` 等于本次 `SOURCE_SHA`，过期工作流拒绝推送。`release` 以观测到的提交为父提交；竞争更新导致正常 Git non-fast-forward 拒绝，绝不通过 force、重置或重新生成旧提交绕过。

`current.json` 另外保存实际发布的 `(sequence, attempt)`：Actions 分别使用 `github.run_number` 和 `github.run_attempt`。同一 main 也可能有不同来源快照，不能只靠源码 SHA 排序；不同产物的序号必须严格大于当前已发布序号，晚到的旧运行不能覆盖较新产物。手动发布与回退必须明确提供序号，不能重新从 1 计数。内容相同仍不创建提交，也不更新入口序号；因此这里保存的是**实际发布水位**，不宣称记录所有跳过的无变化运行。

本地 `.git/airroute-publish/<目的标识>/pending.json` 在 push 前可靠保存目标版本、manifest 摘要、来源 SHA、基线和**确切提交 SHA**。推送超时也按这份 SHA 及提交祖先关系向远端对账。不能确认则保留本地 journal 和工作目录，重复运行同一候选只重试同一提交，不把旧产物重新包装成新提交。另一个候选不能绕过未决记录。远端已前进到其他历史时标记 `superseded`，不覆盖较新版本。

工作流失败时仅上传不含凭据的 `pending.json`。原始来源归档、认证 HTTP header 和暂存 Git config **不上传**。托管 runner 在作业结束后不再可用；跨作业恢复应先根据保存的 SHA 通过 `git ls-remote` / 提交关系人工确认远端，无法找回本地尚未上传的 Git 对象时重新构建当前 main，不能声称自动恢复了丢失对象。重新构建仍须通过来源固定、完整验证、当前 main 和 release 的竞争检查。

成功的发布结果分别报告候选版本、生成提交与远端确认提交；构建成功不等于远端发布成功。

## 权限和来源 Secrets

构建 job 只读仓库，发布 job 才有 `contents: write`。使用仓库自带 `GITHUB_TOKEN`，无需创建 OAuth App、仓库 PAT 或新的仓库。Actions 已固定到官方 action 的提交 SHA；升级时核对官方仓库后更换。

可选来源使用 `MAXMIND_ACCOUNT_ID`、`MAXMIND_LICENSE_KEY`、`IPINFO_TOKEN`、`IP2LOCATION_TOKEN`，只通过环境变量提供给获取步骤。缺失来源如实记入快照和质量报告；是否可发布由质量门槛判断，不伪造五源覆盖。不把密钥写入来源 URL、manifest、日志或最终产物。原始供应商文件和缓存只在本地/runner 暂存，发布前依据来源许可与 attribution 规则处理公开衍生物，详见 [SOURCES.md](SOURCES.md)。

## 本地命令

```sh
python -m airroute_data snapshot --output .build/snapshot
python -m airroute_data build --snapshot .build/snapshot/snapshot.json --output .build/candidate
python -m airroute_data validate .build/candidate
# 此命令会更新 origin/release；只在明确准备发布时运行：
python -m airroute_data publish --candidate .build/candidate --repo . --source-sha "$(git rev-parse HEAD)" --sequence <递增序号> --attempt 1
```

回退使用 `python -m airroute_data rollback --version <data_version> --repo . --source-sha "$(git rev-parse HEAD)" --sequence <递增序号> --attempt 1`：验证历史版本文件后，以正常向前提交只切换入口；不使用 `git reset`、历史改写或 force push。调用者仍须有发布授权。

验证覆盖真实本地 bare Git 初次发布、无变化、两个完整版本、向前回退、远端 hook 拒绝、分支竞争、push 成功但响应丢失、未决记录防绕过，以及候选路径逃逸、符号链接、未列出文件和不可变目录碰撞。这些隔离测试不会推送 GitHub，也不代替实际安装 Actions 后的线上工作流验收。
