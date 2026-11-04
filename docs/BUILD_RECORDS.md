# 构建记录与结果反查

构建记录用于解释本轮**实际执行的策略和结果**，不以历史数量或异常幅度决定发布。它复用已有来源快照、域名阶段记录、地域来源冲突、ASN 观测、覆盖比较和发布 journal。详细记录不进入用户订阅的 `.list`、`special/asn.ardb`，也不是另一套在线审计服务。

## 本地生成与保存

同一次获取和构建使用同一个记录目录。输入、候选仍使用新的空目录：

每一轮生成使用新的记录目录；可在同一目录记录获取和随后的一次生成。已经生成过的目录不会被覆盖或混入下一轮数据；错误复用时会告警并跳过诊断，请指定新的 `--record-dir`。

```sh
python3.12 -m airroute_data snapshot \
  --output .build/input --record-dir .build/record
python3.12 -m airroute_data build \
  --snapshot .build/input/snapshot.json --output .build/candidate \
  --baseline .build/previous --record-dir .build/record
```

首次没有正式基线时省略 `--baseline`，记录会说明无可比较的上一版，不能把首次候选当成已发布版本。`build-domains` 也支持 `--record-dir`；被复用的地域 IP 列表与 ASN 数据库必须标为旧基线数据，不能声称本轮重新解析了它们。

记录目录包含：

| 内容 | 用途 |
| --- | --- |
| `overview.md` | 人类可读总览：状态、来源、异常、比较和产物位置 |
| `summary.json` | 源码与构建身份、各阶段状态、计数、诊断完整性和错误 |
| `effective-config/` | 生效配置的脱敏副本及对应摘要；秘密值不会被复制 |
| `trace.sqlite3` | 本地只读反查所用索引，保存输入范围、处理事件、未决范围和输出关联 |
| `comparison.json` | 可完成时的上一正式版与本轮候选比较；前缀数、地址量和域名语义覆盖分开解释 |
| 现有详细报告 | 来源、选择器、地域 IP、ASN、CN/RU、LAN、Real IP、服务商和类别的既有统计 |

`trace.sqlite3` 只是批处理诊断文件，不是恢复旧控制中心数据库或新增常驻服务。来源原始范围只记录一次，最终大区/ASN/规则关联通过索引查询，不逐 IP 展开数据库。采样报告不是完整逐条证据；完整性、被省略内容和数量以记录中的标记为准。

## 按域名、IP、ASN 或集合查原因

```sh
python3.12 -m airroute_data explain --record-dir .build/record \
  --domain example.com
python3.12 -m airroute_data explain --record-dir .build/record \
  --ip '2400::/32' --limit 100 --offset 0
python3.12 -m airroute_data explain --record-dir .build/record --asn 13335
python3.12 -m airroute_data explain --record-dir .build/record \
  --product category/ai
```

最终 IP/CIDR/ASN 规则统一为两字段，不输出 `no-resolve`，包括上游显式携带的标志；已知标志的剥离属于明确的 AirRoute 转换策略，并在转换记录中注明来源及原因。IP/ASN 索引用规范化基础值查询；地址覆盖统计只描述地址集合。

域名查询关联原始来源、选择器/include、属性和语义转换、过滤原因、集合包含关系及最终规则。父后缀覆盖子域或 CIDR 合并会显示覆盖关系；不能将压缩后文本消失当成语义丢失。某条记录未出现在来源中只表示缺少信息，不能推断它被反对。

IP 或前缀查询展示来源给出的原始范围、国家值和归一化大区、已有冲突/未知状态及最终产物。一个前缀内可能有多个决定；不能用起始 IP 的判断外推整个前缀。大量结果使用 `--limit`/`--offset` 分页，截断页不代表全部记录。ASN 查询保留多起源、采集视角和被隔离的超大宣告，服务商/类别查询使用实际产品 ID。

地域 IP 输出使用固定主源与有序备选补缺；发生分歧时保留主源/已选备选结果，并把异议与最终选择一起记录。`geo_issue` 和 `largest_conflict_or_unknown_ranges_sample` 同时包含仍被输出的冲突与真正未知，不再把冲突等同丢弃。`explain` 返回 `source_selection`、`recorded_conflicts` 和独立的 `unknown_reasons`。

IPv6 总览同时提供地址量和前缀数；已观察的原始 BGP 宣告与派生 IP-to-ASN 区间分别计数。没有观察到宣告不等于不存在路由，观察到宣告也不证明物理位置。采集快照、视角和超大宣告隔离会限制这项对照；不能用注册地、ASN 或 BGP 自动修正地域。

注意两个口径不同：既有 `reports/auxiliary.json` 中的合成 `bgp-visible` 视图使用的是**观察宣告与派生 ASN 数据的合并覆盖**，名字不能理解为逐条原始 BGP 证据。新记录 `summary.json` 的 `bgp` 使用本轮原始非默认路由宣告，单独统计仅表达转发的默认路由，排除派生 IPtoASN 区间；宽前缀保留并单独报告，不表示整个范围被某 ASN 独占。默认路由 `::/0` 不会把全部 IPv6 都标成可用于地域对照的已宣告地址。比较时应查看该字段的 `scope` 和采集来源，不能混用两种统计。

## 失败和发布状态

客户端产物只有 `region`、`category`、`provider`、`special` 四类。CN 拆为 `region/cn-ip` 与 `region/cn-domain`；其他地域只有 IP，RealIP 合并为 `special/realip`，仅生成 `special/asn.ardb` 数据库，不再生成 Geo 数据库。历史路径变更会在比较中表现为产品迁移，不应解释为地域或匹配语义丢失。

来源状态区分未选择/未启用、凭据缺失、下载失败、解析失败和有效输入为空。计数注明是物理行、候选记录、成功解析记录、展开后的选择器记录，还是去重后的路由观测；它们不能混为 SQL 次数或独立证据票数。

构建在能够继续的范围内记录已完成阶段；失败不会伪装成空输出成功。完整性或格式检查失败时，已产生的候选统计、冲突和比较仍尽可能保存。若在文件生成前已失败，就明确说明哪些下游内容不存在。诊断整理失败也不会改写主构建的原始异常或使失败变成成功。

构建、候选校验和发布是不同状态。手动关闭发布、构建未通过、发布命令尚未启动、Git 拒绝、传输结果未知以及已核实发布分别记录。只有发布器核实的 commit 才代表远端正式版本；候选目录存在、Actions 的构建 job 成功或上传 artifact 均不等于已发布。

来源获取成功使用 `acquisition-success`，不能被误读为整个构建成功；每次生成操作开始后标为 `running`，结束时才保存终态。Actions 另外记录 workflow job 的结果。当进程被中断而没有写完终态，后续尽力执行的状态步骤会将仍在 `running` 的操作标为 `interrupted`，不会沿用前一次获取成功的状态。若 runner 被直接销毁，连状态步骤与 artifact 上传也未执行，则只能依赖此前已持久化记录和 Actions 的 job 结果，不能宣称有完整终态证据。

发布任务也始终尽力记录 job 结果，同时保留发布器已经写出的已核实 commit、无变化结果或未确认恢复状态；不能为了写入 workflow 状态而覆盖这些身份。发布进程中断时不会据此推断远端成功，也不会自动重推。

## Actions artifact 和保留时间

在一次 Actions run 页面的 **Artifacts** 下载：

- `build-record-<run_id>-<attempt>`：成功或失败构建的诊断包，保留 **7 天**。
- `publication-record-<run_id>-<attempt>`：发布 job 的独立结果，保留 **7 天**。构建被跳过或禁止发布时，原因在 build-record 中，不会虚构一个发布 job。
- `publication-journal-<run_id>-<attempt>`：既有发布恢复身份，在发布失败且已产生 journal 时保留 **7 天**。
- `candidate-<run_id>-<attempt>`：只有生成和验证步骤通过才上传，保留 **1 天**，用于后续发布；它不是正式规则订阅地址。

诊断打包使用 `record-pack` 压缩索引和详细数据，预算为 **1 GiB 压缩包内容**；`artifact-index.json` 记录实际体积、摘要、保留文件和完整性。超预算时按完整文件排除，不截断 SQLite 数据库；清单会将包标为不完整，不能声称全量证据仍可查询。本地原始记录不因打包而删除。下载后先阅读包内清单，将 `trace.sqlite3.gz` 解压到同目录的 `trace.sqlite3` 再运行上述 explain 命令。

```sh
python3.12 -m airroute_data record-pack \
  --record-dir .build/record --output .build/diagnostics
# 下载并解压 Actions 外层 zip 后，如存在 trace.sqlite3.gz：
gzip -dk .build/downloaded-record/trace.sqlite3.gz
python3.12 -m airroute_data explain \
  --record-dir .build/downloaded-record --domain example.com
```

所有诊断打包/上传步骤均独立尽力执行，失败不掩盖原始构建错误。原始供应商归档、未脱敏的配置、Token、密码、授权头及带凭据的 URL 不进入诊断包；要求原始供应商文件才能复核的细节只能依照许可、凭据与输入摘要另行取得。

`overview.md` 和 `summary.json` 保持直接可读；其他较大的 JSON 可按清单标为 `.json.gz`，阅读前解压。`artifact-index.json` 的 `complete` 表示文件是否全部装入包；`source_evidence_complete` 记录原始生成证据链状态，`evidence_complete` 同时要求原始证据完整且打包未遗漏。来源缺失状态仍应单独查看。

## 可追溯边界

- 旧 run 只能使用当时已保存的 artifact。之前没有上传的 IPv6 逐条冲突或原始输入不能凭新功能追溯补造；已过期 artifact 也不能保证恢复。
- 成功解析的记录保留用于判断的语义值、原始范围和来源引用，不逐字节保存原始行。需要核对原始 CSV 排版、全部供应商字段或完整下载文件时，须按来源版本和摘要重新取得合法可用的原文件。
- ASN 可以查询本轮多起源输入、处理原因和最终前缀；当前比较记录没有完整逐 ASN 的前后差分，不能将 地域 IP 区间差分误认为 ASN 变更清单。
- 来源和配置固定到摘要，但记录不证明上游地理结论或服务身份绝对正确，也不证明各发行者统计独立。
- 未执行的阶段、未解析的来源、被裁剪的诊断或已复用的基线数据均明确标识，不能把缺失解释成无冲突。
- 记录描述本轮固定快照，不查询当前在线目标、不主动测量，也不修改客户端或正式订阅数据。
