# 构建、发布与回退

源码、配置和 Actions 位于 `airrelay/airroute-rules` 的 `main`。最终产物继续发布到现有 `airrelay/rules` 的 `main`：本次已明确确认保留这个实际目标，不改为 `release`，也不恢复源码仓库旧 `release` 分支。下面所有订阅路径均以 `https://raw.githubusercontent.com/airrelay/rules/main/` 为前缀。

工作流每天 03:17 UTC 或手动运行。手动参数 `publish=false` 只生成和验证候选、保留构建记录，不执行发布 job。生成或验证失败时，上一已发布提交保持不变。

## 四类产物与路径迁移

发布树平铺，不使用版本目录或哈希路径：

```text
manifest.json
regions.json
ATTRIBUTION.md
region/cn-ip.list
region/cn-domain.list
region/<其他既有大区>.list
category/*.list
provider/*.list
special/*.list
special/asn.ardb
```

客户端规则只有 `region`、`category`、`provider`、`special` 四个顶层分类。`manifest.json`、`regions.json` 和许可说明是配套元数据。完整构建报告、冲突索引和失败诊断保存在 Actions artifact，不进入订阅目录。

- `region/cn-ip.list` 只有 IPv4 / IPv6；`region/cn-domain.list` 是大陆非 IP 规则。旧 `region/cn.list` 停止生成，不保留语义悄悄变化的兼容文件。
- 其他地域列表，包括 `region/ru.list`，都只有 IP。俄罗斯服务域名按用途留在 `category/ru-services.list` 等服务集合。
- 原 `service/*.list` 迁入 `provider` 或相应 `category`，以 manifest 的 `product_catalogue` 和配置中的迁移映射为准；不能将单个服务自动解释为其整个母公司。
- 原 `dns/realip.list` 和可选扩展合并为 `special/realip.list`。它是 DNS 返回真实地址模式的名单，不表示直连、解析器或出口动作；客户端订阅入口与 RealIP 导入路径需要同步修改，数据发布不会自动修改客户端。
- 不再生成或发布 `geo.ardb`。地域定位结果直接输出地域 IP 列表；ASN 只保留 `special/asn.ardb`，继续使用 ARDBv001 v1 的 ASN 契约。

发布器重建整个产物树，因此旧 Geo、`service`、`dns` 和旧 CN 路径会从最新提交删除。旧 Git 提交仍可追溯，但旧路径的消费者必须迁移，不能继续把缓存内容当作最新数据。源仓库、产物仓库及客户端中的订阅目录、下载 URL 和 RealIP 导入配置都应按新 manifest 对接。

## 验证与一致版本

构建固定来源快照和配置摘要，保留解析、归类、转换、包含关系、去重、冲突和覆盖变化。本轮已选择且启用的来源缺凭据、下载或解析失败都必须失败，不以旧快照顶替；明确未启用/未选择的可选源和不存在的比较基线分别报告未参与/跳过。主地域源、正式 MaxMind ASN、冻结 IANA 四源不可缺失，不造数。历史数量、增减幅度、最低规则条数和来源投票数只用于说明，不阻止发布。

发布前仍核验格式、类型、长度、SHA-256、封闭文件清单、符号链接和路径安全、ASN 二进制双栈和边界、规则与 manifest 的一致性。不能因为取消历史数量门槛而绕过这些工程检查。发布器的二次验证同样不加载旧数量策略、不以历史覆盖缩水判断内容错误。

所有正式文件在同一个 Git commit 中更新，以普通非 force push 原子切换整棵树。消费者应先固定产物仓库的提交 SHA，再按该 SHA 下载 manifest 和所有需要的文件并核对长度、摘要；连续请求可移动的 `main` URL 仍可能跨更新混版。

数据版本由实际数据及生效配置决定。相同版本对应不同正式内容时失败；相同完整产物树不创建无意义提交。重新获取相同内容时，新的获取时间只描述本轮执行，不能造成同版本碰撞或新提交；已发布 manifest 保留原始生成的获取时间，本轮新时间仍保存在构建记录中。比较只忽略明确的获取时间，来源版本、摘要和文件内容仍必须一致。没有 `versions/<hash>/` 或 `current.json` 长期兼容入口，通过 Git 历史保留旧版本。

普通 Git 文件在本项目中限制为 95 MiB，为 GitHub 的单文件 100 MiB 限制留余量。ASN 不整体压缩；报告在候选中分片，完整详细索引另作诊断 artifact。

## 并发、传输失败和恢复

Actions 的并发组禁止两个生成/发布工作流同时推进。发布前检查源码远端 `main` 仍等于本次 `SOURCE_SHA`；产物目标使用观测到的父提交，目标竞争通过普通 Git non-fast-forward 拒绝。绝不 force，不重新 fetch 后把旧候选包装成新提交。

manifest 的 `publication` 记录实际发布的 `(sequence, attempt)`；Actions 使用 `github.run_number`、`github.run_attempt`。同一源码可能有不同来源快照，旧运行不能覆盖新运行。无变化跳过不更新已发布水位。

推送前，`.git/airroute-publish/<目的标识>/pending.json` 保存目标版本、源码 SHA、原目标 SHA 及确切待推送提交 SHA。超时后按这份 SHA 和提交关系对账；无法确认就保留未决状态。其他候选不能覆盖未决记录，也不能重新生成提交盲推。

托管 runner 在作业结束后会消失。失败时只上传不含凭据的 journal；暂存 Git 配置、授权头和原始供应商归档不上传。跨作业恢复要先按保存 SHA 核实远端；找不回尚未上传的 Git 对象时，应重新构建当前源码，不能声称已自动恢复原对象。

首次覆盖产物仓库早期无 manifest 的树仍需显式匹配原目标 SHA，保留原有普通向前提交保护；不会因此切换成另一仓库的旧基线。比较基线不存在时，本轮正常生成并明确报告比较跳过。

## 权限、密钥与命令

构建 job 使用只读权限。跨仓库发布使用源码仓库 Secret `RULES_PUBLISH_TOKEN`，仅授权 `airrelay/rules` 的 Contents 读写权限；当前仓库的 `GITHUB_TOKEN` 不能自动获得跨仓库写权限。凭据不能写入 remote URL、报告或产物。

来源密钥为 `MAXMIND_ACCOUNT_ID`、`MAXMIND_LICENSE_KEY`、`IPINFO_TOKEN`、`IP2LOCATION_TOKEN`，只注入获取步骤。Actions 固定官方 action 提交及 `ubuntu-24.04`，不依赖 `ubuntu-latest` 自动变更系统版本。

```sh
python3.12 -m airroute_data snapshot --output .build/snapshot --record-dir .build/record
python3.12 -m airroute_data build --snapshot .build/snapshot/snapshot.json \
  --output .build/candidate --record-dir .build/record
python3.12 -m airroute_data validate .build/candidate
# 只有明确准备发布时才运行；products 指向 airrelay/rules：
python3.12 -m airroute_data publish --candidate .build/candidate --repo . \
  --source-sha <源码提交> --sequence <递增序号> --attempt 1 \
  --remote products --branch main --source-remote origin
```

回退也使用普通向前提交，不 reset 或 force。只能回退到符合当前四类产物及 ASN 契约的历史版本；含旧 Geo/旧分类的版本不是当前客户端契约的合法候选。回退或正式发布仍需要相应授权。

诊断 artifact 的目录、查询方式、完整性标记和保留时间见 [BUILD_RECORDS.md](BUILD_RECORDS.md)。候选存在、构建通过和 artifact 上传均不等于正式发布，只有远端确认的提交才是已发布版本。
