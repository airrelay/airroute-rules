# 数据来源、访问要求与事实边界

注册表为 [`config/sources.json`](../config/sources.json)，核验日期 **2026-11-03**。这是公开资料的批量下载系统，没有目标 DNS、TLS、HTTP、ICMP、Globalping、自有探针或逐目标 WHOIS 查询。

## 五条全球地域发布链

| 发布链 | 免费格式 / 双栈 | 注册、配额与更新 | 字段与默认状态 |
| --- | --- | --- | --- |
| [MaxMind GeoLite Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) | Country CSV ZIP，IPv4/IPv6 Blocks 和 Locations | 免费账户，`MAXMIND_ACCOUNT_ID`、`MAXMIND_LICENSE_KEY`；HTTP Basic；每日最多30次库下载；周二/五及临时更新 | Blocks `geoname_id` 对应位置国家；`registered_country_geoname_id` 是注册地，不能补作位置。已启用获取、解析和派生融合；许可义务见下文 |
| [DB-IP Country Lite](https://db-ip.com/db/lite.php) | 月度 CSV gzip，IPv4+IPv6同文件 | 无账户或令牌；月度完整快照，不是增量 | `ip_start,ip_end,country` 为国家位置估计；Lite覆盖及精度有降级；CC BY4.0，随产物署名 |
| [IPinfo Lite](https://ipinfo.io/developers/ipinfo-lite-database) | `ipinfo_lite.csv.gz`，双栈；亦有JSON/MMDB/Parquet，本项目只取CSV | 免费账户及 `IPINFO_TOKEN`；每日更新 | 当前 `network,country,country_code,continent,continent_code,asn,as_name,as_domain`；国家字段是IP位置估计，ASN主体另论。CC BY-SA4.0。无令牌的公开100行sample只能测试，不能冒充完整来源 |
| [IP2Location LITE DB1](https://lite.ip2location.com/database/db1-ip-country) | IPv4/IPv6两份CSV ZIP，十进制起止地址 | 免费账户及 `IP2LOCATION_TOKEN`；LITE下载已迁至IP2Location.com。当前DB1页显示半月更新，FAQ/下载器仍建议每月首周随机一天下载，以实际载体为准 | `ip_from,ip_to,country_code,country_name` 为国家位置估计；IPv6按128位解释，不能按数值大小猜族。免费署名/share-alike条款；无凭据明确缺源 |
| [IPLocate Country](https://github.com/iplocate/ip-address-databases) | 官方Country CSV ZIP，双栈；固定commit的LFS media原文件 | 无账户/令牌，无逐IP API；每日发布链 | `network,continent_code,country_code,country_name` 是国家位置估计；不能替换成ASN-holder country。CC BY-SA4.0，随产物署名 |

按项目要求，MaxMind 已启用公开派生构建，处理位置国家字段，跟其他有效地理来源一起融合。保留 MaxMind 署名、CC BY-SA 及 GeoLite EULA 条款。该开关不表示 Git 历史保留已经满足旧数据删除及下游义务，历史清理需另行安排；不自动删除或重写历史。

[IP2Location官方下载器](https://www.ip2location.com/free/downloader)定义现行端点、令牌与HTTPS重定向。实际download code如发生变更应修订配置，不能猜测或绕过登录权限。官方免费频率要求优先于本项目计划。

状态 `missing-credentials`、`unavailable`、`disabled`、`not-selected` 都不构成一票“国外”。当轮真实可用数量以 `snapshot.json` 和构建报告为准，不用注册条目数或测试样本凑齐五家。不同发行者可能共享未公开的geofeed/BGP/RIR上游，**publisher不同不等于统计独立**。`lineage`阻止已知镜像、格式与衍生重复计票，不声称掌握所有隐藏相关性。

## BGP、ASN、注册与geofeed

- [RIPE RISwhois批量文档](https://www.ris.ripe.net/docs/ris-whois/)：IPv4/IPv6 dump汇总多RIS视角；现行文档说明按请求生成，不能继续沿用旧“每日更新”描述。保留origin-AS集合和更具体前缀，peer/collector可见性不是物理位置。
- [RouteViews官方归档](https://archive.routeviews.org/)：固定collector、月份和最后完整MRT RIB，解析TABLE_DUMP_V2双栈及多起源。这是采集视角快照，不能当全网完整真相；新快照替换旧快照，撤销/消失路由不能靠无限append保留。
- [IPtoASN](https://iptoasn.com/)：官方双栈TSV gzip每小时更新，PDDL1.0；字段为起止地址、ASN、country、description。用于ASN辅助；country不是位置投票，单值映射不能替代有MOAS的真实RIB。已停用的逐目标public API不接入。
- [APNIC delegated](https://ftp.apnic.net/stats/apnic/)和[RIPE delegated](https://ftp.ripe.net/pub/stats/ripencc/)：资源分配/登记国家、状态及范围，仅作注册背景。分配、通告、实际位置三种覆盖分开，未宣告/撤销网段不凭登记国家变成位置事实。
- [bgp.tools官方导出](https://bgp.tools/kb/api)：确有 `table.jsonl`，含CIDR、ASN、Hits。禁止爬人工页面；要求可联系的识别User-Agent，至少间隔30分钟。默认禁用，配置 `BGPTOOLS_USER_AGENT` 后才可开启，Hits不变成置信分。
- RFC8805 geofeed为运营者自报范围国家/地区，仅辅助比较，不能单独成为位置真值。载体、运营者与范围独立记录；一个IP不能扩张整个前缀。公开载体下载失败如实记录，不偷偷替换同名来源。
- 本版不接入有访问约束的整库RDAP/企业身份/证书透明度资料，也不逐目标查询。未来批量接入需先定义主体语义：CA不是持有人，企业不是单一产品，隐私隐藏不是反证。RPKI有效亦不证明地域；本版没有把接口或类型存在包装成已取得地理证据。

## 中国大陆专项

| 来源 | 核验的血缘及维护 | 本项目用途 |
| --- | --- | --- |
| [17mon/china_ip_list](https://github.com/17mon/china_ip_list) | IPIP.NET；README明示通常季度更新、包括WHOIS但未宣告地址、骨干网可模糊化；CC BY-NC-SA4.0 | 下载留存状态和血缘，`publish_allowed=false`；当前不进入公开派生，也不进入辅助覆盖计算。不能把“已下载”说成“已经用于融合/核查” |
| [misakaio/chnroutes2](https://github.com/misakaio/chnroutes2) | 每小时更新，feed含AS917、AS906、AS131477、AS138195等；CC BY-SA | CN路由背景而非位置真值，单项目及格式只算一个血缘 |
| [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) | 运营商ASN/BGP分类，`ip-lists`生成分支含 `china.txt`、`china6.txt`，代码MIT | 双栈运营商路由覆盖比较，同一生成链不拆票 |
| [blackmatrix7 China/ChinaMax](https://github.com/blackmatrix7/ios_rule_script) | 选择Surge原始列表；ChinaMax_Domain实际路径 `rule/Surge/ChinaMax/ChinaMax_Domain.list` | 成熟域名市场/分流分类直接输入；IP 部分单作辅助，不把 ChinaMax 当物理位置证明，不按格式镜像加票 |
| APNIC/RIS/RouteViews/geofeed | 注册、BGP、自报分别建模 | 范围边界和冲突统计，不能仅凭辅助线索扩张大陆 |

大陆只有一个公开 `region/cn.list`；内部域名/IP拆分只是处理步骤。域名 CN 表达服务面向的市场和分流用途；与 IP 位置估计是两条证据链。明确主分类可以直接贡献域名，身份资料不是每条规则的前置门槛。混合、共享或不明用途仍分别处理，不能靠 TLD/CDN/登记地自动归类，也不能把其他列表未收录当作反对。报告分开域名市场分类、IP 位置估计及路由参考，不相加称为准确率。

## 俄罗斯与服务域名

RU从当轮可用全球位置估计提取，结合RIPE登记、RIS/RouteViews/geofeed对照，独立大区ID由版本化 `config/regions.json` 定义；欧洲/亚洲不能重复包含RU。`.ru`、俄罗斯登记 ASN、访问限制均不单独证明服务身份或物理位置。俄罗斯域名可表达服务身份、面向市场的分流用途或明确地域端点，不能混为一类；IP 覆盖/冲突与域名覆盖/混合用途分别统计。

[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)为主要基础之一；固定commit，解析include、属性、精确、后缀、keyword、regexp原义。Sukka实际生成库为[SukkaLab/ruleset.skk.moe](https://github.com/SukkaLab/ruleset.skk.moe)。[ACL4SSR](https://github.com/ACL4SSR/ACL4SSR)与blackmatrix7仅选择V2Ray/Clash/Mihomo/Surge相关资料；同规则的格式、镜像及生成库不作独立多票，参考新增项不盲并集。UA、MITM、rewrite模块不接入。

[Microsoft365官方机器目录](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service)含serviceArea、category、required及端点范围。只处理相应服务，不把整个Microsoft/CDN/CA视作Office。GUID是下载客户端关联标识而非密钥，配置可换为使用方自己的GUID；接口429不轮换GUID绕过。

## 快照与重放

1. 下载在计算前完成。GitHub先把branch固定为40位commit，再抓同一commit的少量文件或DLC归档。HTTP固定已得字节，逐块SHA256，记录实际ETag/Last-Modified（如有）；无上游版本时以内容摘要命名，不伪造日期。
2. 解压拒绝绝对路径、`..`、链接、特殊文件和重复覆盖，限制下载/展开体积及成员数。跨源HTTPS重定向剥除Authorization/Cookie，不降级HTTP。环境凭据及原始异常URL不写日志或产物。
3. 最后写 `snapshot.json`，非空目录不允许隐式刷新。构建前复核路径、长度和树摘要。原始厂商资料不进入公开release或Actions artifact。
4. `fetched_at`只是获取时间，不是发布日期或精度；只保留于输入快照，公开版本稳定身份不因重新获取相同字节的时间而改变。
5. 独立可完成的来源继续处理，缺源不伪称达到五源或准确性目标。官方访问配额、月度建议及限速优先，不换账户/改GUID/爬登录页绕过。


## 新接入的官方目录与未接入候选（2026-11-03）

- [Microsoft 365中国云](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges-21vianet)的官方JSON，免费、无账号；只将中国云目录中的区域特定域名加入大陆集合。非区域公共依赖保留拒绝原因。与worldwide目录属于同一Microsoft血缘，绝非两票。
- [GitHub meta API](https://docs.github.com/en/rest/meta/meta#get-github-meta-information)，免费公共JSON。分别选择website/packages/actions/codespaces及Copilot的域名，限定对应产品身份范围；`*.azureedge.net`等通用依赖不取得Github身份。API限制服从提供商，不主动测量域名。
- [Telegram官方网络目录](https://core.telegram.org/resources/cidr.txt)，免费公开IPv4/IPv6文本，按实际下载摘要固定；Last-Modified旧不自动表示名单无效，来源没有宣称每日变更。它表示服务目标网络，不表示国家，更不是整个ASN。
- Russia 专项保留 DLC `category-ru` 的具名银行、通信运营商、政府、教育、电商、媒体、旅行、产品等 include 成员，单独排除 `tld-ru` / `tld-su` 这类全后缀快捷项，不再丢掉整个聚合分类。属于同一条 DLC 血缘，不能宣称获得多个独立俄罗斯来源。
- [runetfreedom/russia-domains-list](https://github.com/runetfreedom/russia-domains-list)的可访问范围信息不等于服务器位置或服务身份，且所核页面未给出可直接用于本项目公开派生的清晰许可；未并入。被封锁清单更不能当俄罗斯服务清单。
- [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)的加速名单描述 DNS/访问用途，其生成条件不能变成物理位置或公司归属真值。本次没有额外接入它；不把已存在于衍生源的内容再算独立支持。ChinaMax 的普通域名按其分类直接接纳，仅处理明确的类型、范围和冲突例外。

Sukka AI/stream、blackmatrix和ACL4SSR实际解析到选择器；明确地域/市场分类及具名服务来源可以贡献新谓词，不要求候选先被当前身份目录覆盖。ChinaMax 的成熟中国分流分类直接作为域名输入，不要求已有身份目录命中或另一独立来源赞同。仅对公共 TLD 快捷项、已确认冲突、共享基础设施父域、发布者哨兵和无法等价表达的类型作定向纠错；不以来源未知、未被别表收录或域名外观可疑为由一律隔离普通分类成员。相同内容、格式、镜像、可能的共同上游不重复计证。未知血缘如实保留风险说明，不编造逐行上游关系。五家地域来源的账号与许可条件未因新增官方服务目录而改变；仍不能把两个真实国家库说成五源。

## 产品目录、LAN 与 Real IP 来源核查

- blackmatrix7 选择固定 commit 的具名 Surge 服务文件，覆盖 Google Drive、OneDrive、Teams、Claude、Gemini、GitHub/GitLab、Docker、Notion、通信、流媒体和游戏服务；它们是对应服务候选，不授予云客户、共享 CDN 或整个 ASN 服务身份。Microsoft 365 仍优先官方端点 JSON；没有同名第三方文件不猜路径。
- ACL4SSR 补充 Claude、Gemini、GoogleFCM、Microsoft、Steam、Telegram 与局域网文本；它和 DLC/blackmatrix 可能共享原料，不因发行者增加而成为多票。Sukka 继续使用已核实的 AI 与 stream 生成文本，广泛媒体根域只在已有服务身份范围内使用。
- [IANA IPv4 特殊用途注册表](https://www.iana.org/assignments/iana-ipv4-special-registry/)和[IPv6 注册表](https://www.iana.org/assignments/iana-ipv6-special-registry/)下载 CSV，记录 RFC 引用和地址语义，供 LAN/特殊集合一致性核对。IANA 特殊用途并不等于 LAN：共享地址、组播、文档、基准测试、转换及协议专用空间分别处理，不默认 DIRECT。
- LAN 参考 DLC `private`、blackmatrix `rule/Surge/Lan/Lan.list`、ACL `Clash/LocalAreaNetwork.list` 和 [MetaCubeX 生成的 Mihomo private.yaml](https://github.com/MetaCubeX/meta-rules-dat/blob/meta/geo/geosite/private.yaml)。后者包含公网路由器/控制面板名称；“出现在 private 列表”不足以让整个平台变成本地名称。这些是衍生参考，不是四份独立投票。
- [DustinWin fakeip-filter](https://github.com/DustinWin/ruleset_geodata/blob/mihomo-ruleset/fakeip-filter.list)实际发布在 `mihomo-ruleset` 分支。其[项目 README](https://github.com/DustinWin/ruleset_geodata)将来源追溯至 DLC `category-ntp`、`category-stun` 以及 [ShellCrash 自定义名单](https://github.com/DustinWin/ShellCrash/blob/dev/public/fake_ip_filter.list)。选取可表达的域名语义并逐项说明兼容原因，不能把其中的 `*`、宽泛平台后缀和任意时间通配全部纳入默认 Real IP。输出是 DNS 地址模式输入，不是解析器选择或流量出口。

核查基线为 2026-11-03 release 数据版本 `ecd4792280df834aa809bd55`：28 个普通规则文件、17,589 条跨集合域名规则（有重叠，不是唯一域名数），国家库实际只有 DB-IP 与 IPLocate 两条血缘；MaxMind、IPinfo、IP2Location 均为 `missing-credentials`。RIS 双栈、RouteViews、IPtoASN、APNIC/RIPE 登记、misaka/gaoyifan/ChinaMax 和 Vultr geofeed 确已获取并参与各自 ASN/辅助报告；17mon 仅下载后保留未用状态。但**辅助报告并不赋予这些资料物理位置投票权**。新集合的最终条数以本轮真实构建报告为准，不以源配置条目数量宣称完成。


## CN / RU 域名来源角色修正与实际载体（2026-11-03）

`domain_role` 明确分类主库、分类补充、路由用途补充和旧语料回归基线；它不是可信度分数或独立票数。Geo 凭据缺失不阻塞这些公开域名材料的获取和离线域名生成。

| 来源 / 选中载体 | 角色及注意事项 | 本次冻结解析候选 / 不可表达 |
| --- | --- | ---: |
| DLC 原始 data 分类与 include | 主分类；保留属性语义，单独处理 TLD 快捷项 | 由域名构建逐 selector 记录 |
| blackmatrix `China/China_Domain.list` | 明确中国分流分类补充；`China.list` 中的 DOMAIN-SET 成员分到此伴随文件，不能只读主体而漏掉它 | 3,689 / 0 |
| blackmatrix `ChinaMax/ChinaMax_Domain.list` | 成熟中国市场/分流分类直接输入；无需身份或多票证明，针对类型、范围及明确冲突纠错 | 110,427 / 0 |
| ACL `Clash/ChinaDomain.list` | 直连用途候选，内含系统连通性和其他依赖，不能整体理解为公司国籍 | 635 / 0 |
| ACL `Clash/ChinaMedia.list` | 中国媒体/市场用途候选，含国际服务与精确 CDN 端点，需分用途 | 37 / 1 |
| Sukka `List/non_ip/domestic.conf` | 大陆可用及市场分流主张，不是地理定位；与 CDN 子集共享生成链 | 869 / 4 |
| Sukka `List/non_ip/domestic_cdn.conf` | 国内服务 CDN 用途子集，不可额外算一票，也不授予整个云平台身份 | 19 / 1 |
| 旧客户端固定 `region/cn.list` | 仅作语义迁移基线；逐条上游未知，不能虚构归因或单凭旧成员关系授予新分类 | 112,523 域名 + 23,682 IP；两者分开 |

计数是解析谓词，不是最终接纳、真实新增网站或准确率；保留精确/后缀原义，Sukka 中不能安全等价表示的通配符不扁平化。Sukka 各生成文件插入的发布者 canary `7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe` 不是业务端点，不能作为新大陆服务发布。

实际载体版本：blackmatrix `0b6897dc17e0c513d25449c935a9694818e32f0c`，ACL `c15bf546085b825afd238e211f750bb7868c7132`，Sukka `136f19cc769a2a1f2878e880c4297cbcd3f34b6f`。获取、固定摘要、解析错误与后续准入分别记录，不能把下载成功直接写成已进入输出。对应本地固定输入为 `.build/regional-sources/input/snapshot.json`，逐文件摘要和解析计数为 `.build/regional-sources/regional-input-counts.json`；它们是验收资料，不进入 release。

旧语料固定到 [airrelay/rules 的 20a3b237 版本](https://github.com/airrelay/rules/blob/20a3b237005292e60b62603e934b3972348366b4/region/cn.list)，原文件 3,923,114 字节，SHA-256 `9e763ebd67e35b23ed8c41bc8a9cb40556e248ee18f2115a6137298b09deb883`。快照的 `sha256` 是包含文件名和长度的树摘要，不能误当作原文件摘要。基线不会跟随移动分支更新；已有全球媒体、第三方依赖及来源未知条目必须留下自己的分类和待核实原因，而不是为了迁移条数全部恢复。

Sukka 的[实际生成器](https://github.com/SukkaW/Surge/blob/master/Build/build-domestic-direct-lan-ruleset-dns-mapping-module.ts)将人工维护的 `DOMESTICS`、domestic.conf 与 domestic_cdn 合并为 domestic；通用 direct.conf 被分别输出，本次不订阅它来推断中国市场。生成器的这些源文件用于核实字段语义，不假装掌握每一行的独立上游血缘。

ChinaMax 固定版[规则说明及来源](https://github.com/blackmatrix7/ios_rule_script/blob/0b6897dc17e0c513d25449c935a9694818e32f0c/rule/Surge/ChinaMax/README.md)说明它合并 China、ChinaIPs、Mainland 类别并排除 Advertising，同时仍标为实验性规则。它继承 ACL4SSR、LM-Firefly、blackmatrix 自有分类、Hackl0us、Loyalsoldier、GeQ1an 和 sve1r 等上游，不是数十份独立证据。域名文件与主体必须一并读取；主体还含 UA、进程和 IP-ASN，拒绝这些不支持类型不能连带丢掉域名。实际存在的 `.ms` 公共后缀、`.aliyuncs.com` / `.myqcloud.com` 共享平台父域需要定向边界处理；这不构成给所有普通域名设置身份前置门槛的理由。详见 [域名来源核查](DOMAIN-SOURCE-AUDIT.md)。

当前域名路径同时消费 China / ChinaMax 主体与 `_Domain`；`domain_only` 不导入其 IP。Core 可表达的 keyword / regex 保留，国家名关键词与 dotless TLD 快捷项定向排除；`gov.cn` / `edu.cn` 具名政教命名空间保留。大陆排除依据 DLC 具名服务的完整覆盖；大陆访问可用性与全球产品的实际相交不自动删除全球父域，逐项报告且不指定顺序。无法证明不相交的 keyword / regex 按组汇总未知模式，不宣称全无重叠，不新增逐条证据平台。
