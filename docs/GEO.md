# 地域与 ASN 数据

本目录描述批处理数据的事实语义。构建只读取冻结的公开下载资料，不对目标域名、地址或服务器发起 DNS、TLS、HTTP、ping 或 traceroute 测量。

## 大区注册表

`config/regions.json` 是 `airroute-regions-v1` 的唯一来源。ID 一经发布不能重分配；新增分组需要新版本。中国大陆 ID 为 1，港澳 2，台湾 3，俄罗斯 9，欧洲 10；其他分组也具有显式 ID。国家映射互斥，俄罗斯不同时落入欧洲、东北亚或中亚。国家代码是来源字段，产品输出粒度始终是注册表中的大区。

当前客户端 Core 的 ARDB v1 读取器存在，但客户端安装层仍须确认这份大区 ID 注册表及版本；“文件能读取”不代表安装层符号键映射已经接入。

## 五条国家数据发布链

`geo.parse_source` 实现以下官方文件格式：

| 格式 | 使用字段 | 不当成位置的字段 |
| --- | --- | --- |
| MaxMind GeoLite2 Country CSV bundle | Blocks 的 `geoname_id` → Locations-en 的 `country_iso_code` | `registered_country_geoname_id` 不作为位置缺失时的兜底 |
| DB-IP Country Lite CSV | `start_ip,end_ip,country_code` | 不推导城市 |
| IPinfo Lite CSV | `network`、`country_code`；也支持官方范围字段 | ASN 名称、ASN 注册国不代替地址位置 |
| IP2Location LITE DB1 CSV | 十进制首末地址、国家代码 | IPv6 文件的地址族显式指定或按官方 IPV6 文件名识别 |
| IPLocate Country CSV | `network,country_code` | ASN 下载的组织国家不进入地域投票 |

下载与许可要求见 [SOURCES.md](SOURCES.md)。没有账号或令牌的来源显示 unavailable；不能用不同文件格式或镜像补成五家数据。可读取不等于可再分发，发布是否准入由来源配置和校验决定。

## 归并策略

1. 将输入统一成地址族、整数首末地址、位置国家、来源与血缘组。按所有输入边界切分，不在整个前缀上直接投票。
2. 同一来源内部更具体的范围覆盖其自身较宽范围；同等范围的矛盾保留为矛盾。多个同源或衍生文件同属一个血缘组，不增加票数。
3. 先将国家映射至项目大区。默认至少两个有信息的血缘组，且所有有信息组都指向同一个大区，才生成该大区数据。单一来源、跨大区冲突、未映射国家和全部缺失均保持未知。这里没有未经证实的“多数准确率”，不同发布者也不保证统计独立。
4. 同一大区内的国家分歧不妨碍大区输出，但仍写入完整争议资料；例如德国与意大利意见都能支持欧洲大区，不能据此宣称某个国家已经确定。
5. CN、RU 的来源候选地址数、已归类和未解决地址数分别统计。`CN` 路由清单、APNIC 分配国、ASN 登记国和 geofeed 只做辅助对照，不靠并集增加大陆覆盖。

地域覆盖契约明确为：IPv4 地址空间扣除代码中的特殊地址排除表，以及 IPv6 `2000::/3` 扣除该表。构建报告明确排除私网、文档、组播和其他列明的不可地域归类地址；剩余契约范围中，所有来源都没有信息的间隙也以 `missing-all-sources` 输出为未知，而不是默认为海外。这里不声称穷尽 IANA 每一条特殊地址状态，修改排除政策须同步测试与文档。

本地候选 / Actions candidate artifact 内的 `reports/geo-issues/part-*.jsonl`（不发布到 release）逐区间保存所有未知和国家分歧（每片最多32MiB，完整顺序由 `reports/geo.json` 的 `issue_files` 索引给出）：首末地址、状态、源国家、血缘和输出大区。`geo.json` 是汇总，`issues` 仅为明确标记截断的诊断样本；不能用样本数代替完整问题数。地址数量使用 Python 整数，不将 IPv6 数量转成浮点。

构建采用短生命周期的本地 SQLite 临时文件排序事件，8 MiB 页面缓存、文件临时排序、流式扫描，退出后删除。它不保存运行状态，也不是旧控制中心数据库的延续。没有按 IP 地址枚举循环。

## BGP / ASN 与辅助证据

`routing.py` 可读 RIPE RIS origin/prefix dump、IPtoASN TSV、IPLocate ASN CSV、可选 BGP.tools JSONL 以及 RIPE/Route Views 的 MRT TABLE_DUMP_V2 全量 RIB。RIR delegated、RFC 8805 geofeed 和 CN CIDR 清单也有解析器，但它们不直接构成 ASN 路由或物理位置真值。

MRT 使用 RFC 6396 的四字节 AS_PATH 编码；peer-index 中 ASN 是两字节并不改变 RIB AS_PATH 编码。保留 AS_SET 的全部可能起源，支持 IPv4/IPv6 单播、四字节 ASN、ADD-PATH，并按实际 collector/peer 视角做最长匹配，再并集各视角的当前起源。一个视角的更具体前缀不会抹掉另一个视角仍观察到的覆盖前缀。不同 ASN 允许共享完全相同的地址范围。

ASN 公开成员资格对原始 BGP 前缀声明默认使用可配置的保守准入边界：IPv4 最短 `/8`，IPv6 最短 `/12`。这个边界只约束 RIS、MRT、BGP.tools 等原始前缀声明；IPtoASN 范围和 IPLocate ASN 数据可能已无损合并多份相邻成员，不得把宽衍生区间误读成一条超级聚合 BGP 宣告。更宽的原始 BGP 路由声明仍在输入快照中，但不进入公开 ASN 地址归属；报告保存来源、AS 集、范围、RIS peer 数和隔离原因，并明确样本是否截断。这是产品准入政策，不表示已证明路由声明为假，也不提供位置判断。真实 RIS 中出现的 AS24785 `2000::/3`（1 peer）和 AS29632 `2000::/6`（3 peers）会因此隔离，避免将兜底超级聚合范围扩张为全网 ASN 所有权；合法宽范围如 `2410::/17`、`2003::/19`、`2002::/16` 保留。

RISwhois 的摘要保留 origin/prefix 和 peer 计数，缺少逐 peer 的完整路径，因此不能宣称具备逐 peer 最长匹配精度；完整 MRT 路径才保留该视角。RIS 中的默认路由 `/0` 明确排除并单独计数，不能把转发兜底误当成 ASN 拥有全网地址。

每次构建仅使用本轮固定 RIB：旧快照中存在、本轮没有的路由不沿用。这个差异表示“在这些当前输入中没有观察到”，不自动等于全球已撤销。增量 UPDATE 流必须有正确的初始 RIB 和撤销重放，本实现明确拒绝将其当作全量 RIB，以免复活撤销路由。RPKI 有效性不提供地理证明。

Blackmatrix China / ChinaMax 的 `surge-cidr-reference` 辅助视图只抽取顶层显式 `IP-CIDR`、`IP-CIDR6` / `IP6-CIDR` 行，不从域名或 AND / NOT 的嵌套内容中挖出地址。它们仍只表示第三方规则引用，不能增加地域票数。

`fuse_routes` 同次扫描还产生无损归并的 `routed_prefixes` 可见前缀并集。`audit_auxiliary(..., routing_prefixes=...)` 直接复用这份并集，作为 `bgp-visible` 辅助视图对照 CN、RU、其他大区和未知，不再重解析大体积 MRT；可见路由本身不是位置票数。

`audit_auxiliary` 对每份清单与清洗后 Geo 数据做真实边界交集，报告候选地址分别落到 CN、RU、其他大区或未知的数量，重叠行不重复计算同一来源覆盖。这样可以发现误收，又不会把路由成员身份或运营商声明冒充物理定位。

## 校验

`python -m unittest discover -s tests -p 'test_geo.py' -v` 覆盖跨边界、同源镜像、来源内部更具体、同大区国家分歧、注册国不兜底、五种格式、缺失全源、IPv6 与特殊地址。

`python -m unittest discover -s tests -p 'test_routing.py' -v` 覆盖多起源、跨视角更具体、双栈、撤销快照不沿用、AS_SET/四字节 ASN/ADD-PATH、MRT 损坏和 UPDATE 拒绝，以及辅助清单对照。测试数据为有说明的合成夹具，不是对全网定位准确率的实测。

规范参考：[RFC 6396](https://www.rfc-editor.org/rfc/rfc6396)、[RIPE RISwhois](https://ris.ripe.net/docs/ris-whois/)、[IPtoASN 数据说明](https://iptoasn.com/)、[RFC 8805](https://www.rfc-editor.org/rfc/rfc8805)。


## 输出与辅助证据的新保护

Geo融合仍要求有效血缘组在大区层面一致，不为扩大文件而用路由、登记国或geofeed覆盖跨区分歧。`source_address_support`分别统计每家资料覆盖、支持输出及仍有分歧的地址数量；各来源之间重叠，不能相加当覆盖或准确率。RIR/geofeed按其真实CN/RU字段分别与清洗结果对照，不再仅显示一个包含所有国家的RIR总量；通用路由列表没有国家字段时不会默认标CN。

Route Views同一RIB前缀、同一起源集合的peer视角共用临时排序载体，仍保存全部peer身份并逐peer做最长前缀选择。更多具体前缀只替换同一视角，其他视角的覆盖声明和多起源不会消失。此处SQLite只是批处理临时外部排序文件，没有恢复在线数据库或主动探测。

地区列表中的域名是明确的当地服务/机构身份，不是Geo物理位置事实；ARDB库仍只包含统一清洗的IP区间。所有地区的IP部分均与Geo对应组逐项验证。发布按各区IPv4/IPv6的地址并集、旧地址保留量、增量与损失分别保护，不以CIDR行数代替覆盖。
