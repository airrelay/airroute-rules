# 数据来源、访问要求与事实边界

注册表为 [`config/sources.json`](../config/sources.json)，核验日期 **2026-11-03**。这是公开资料的批量下载系统，没有目标 DNS、TLS、HTTP、ICMP、Globalping、自有探针或逐目标 WHOIS 查询。

## 五条全球地域发布链

| 发布链 | 免费格式 / 双栈 | 注册、配额与更新 | 字段与默认状态 |
| --- | --- | --- | --- |
| [MaxMind GeoLite Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) | Country CSV ZIP，IPv4/IPv6 Blocks 和 Locations | 免费账户，`MAXMIND_ACCOUNT_ID`、`MAXMIND_LICENSE_KEY`；HTTP Basic；每日最多30次库下载；周二/五及临时更新 | Blocks `geoname_id` 对应位置国家；`registered_country_geoname_id` 是注册地，不能补作位置。默认可下载/解析/内部比较，不进入公开派生，原因见下文 |
| [DB-IP Country Lite](https://db-ip.com/db/lite.php) | 月度 CSV gzip，IPv4+IPv6同文件 | 无账户或令牌；月度完整快照，不是增量 | `ip_start,ip_end,country` 为国家位置估计；Lite覆盖及精度有降级；CC BY4.0，随产物署名 |
| [IPinfo Lite](https://ipinfo.io/developers/ipinfo-lite-database) | `ipinfo_lite.csv.gz`，双栈；亦有JSON/MMDB/Parquet，本项目只取CSV | 免费账户及 `IPINFO_TOKEN`；每日更新 | 当前 `network,country,country_code,continent,continent_code,asn,as_name,as_domain`；国家字段是IP位置估计，ASN主体另论。CC BY-SA4.0。无令牌的公开100行sample只能测试，不能冒充完整来源 |
| [IP2Location LITE DB1](https://lite.ip2location.com/database/db1-ip-country) | IPv4/IPv6两份CSV ZIP，十进制起止地址 | 免费账户及 `IP2LOCATION_TOKEN`；LITE下载已迁至IP2Location.com。当前DB1页显示半月更新，FAQ/下载器仍建议每月首周随机一天下载，以实际载体为准 | `ip_from,ip_to,country_code,country_name` 为国家位置估计；IPv6按128位解释，不能按数值大小猜族。免费署名/share-alike条款；无凭据明确缺源 |
| [IPLocate Country](https://github.com/iplocate/ip-address-databases) | 官方Country CSV ZIP，双栈；固定commit的LFS media原文件 | 无账户/令牌，无逐IP API；每日发布链 | `network,continent_code,country_code,country_name` 是国家位置估计；不能替换成ASN-holder country。CC BY-SA4.0，随产物署名 |

免费不代表没有分发条件。[GeoLite EULA](https://www.maxmind.com/en/geolite/eula) 和[适用义务说明](https://support.maxmind.com/knowledge-base/articles/who-is-covered-by-the-geolite-end-user-license-agreement) 要求维护更新、删除旧版本，并向再分发使用者传递相应义务。当前长期保存不可变release的策略不自动满足这些义务，因此MaxMind默认 `publish_allowed=false`：可获取/分析，不参与公开Geo派生。不是仅增加一行署名就宣称解决。未来调整需要同时解决保留期限与使用条款；不绕过或购买额外许可。

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
| [17mon/china_ip_list](https://github.com/17mon/china_ip_list) | IPIP.NET；README明示通常季度更新、包括WHOIS但未宣告地址、骨干网可模糊化；CC BY-NC-SA4.0 | 内部覆盖/冲突审计，默认不进入公开派生，不简单并入大陆 |
| [misakaio/chnroutes2](https://github.com/misakaio/chnroutes2) | 每小时更新，feed含AS917、AS906、AS131477、AS138195等；CC BY-SA | CN路由背景而非位置真值，单项目及格式只算一个血缘 |
| [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) | 运营商ASN/BGP分类，`ip-lists`生成分支含 `china.txt`、`china6.txt`，代码MIT | 双栈运营商路由覆盖比较，同一生成链不拆票 |
| [blackmatrix7 China/ChinaMax](https://github.com/blackmatrix7/ios_rule_script) | 选择Surge原始列表；ChinaMax_Domain实际路径 `rule/Surge/ChinaMax/ChinaMax_Domain.list` | 域名身份及IP来源参考，不把ChinaMax扩展当位置证明，不按格式镜像加票 |
| APNIC/RIS/RouteViews/geofeed | 注册、BGP、自报分别建模 | 范围边界和冲突统计，不能仅凭辅助线索扩张大陆 |

大陆只有一个公开 `region/cn.list`；内部域名/IP拆分只是处理步骤。国内服务与海外provider/category排除按服务身份和可表达条件执行；混合、共享或不明身份不能靠TLD/CDN/登记地自动归类。报告分开大陆物理来源覆盖和路由参考覆盖，不能相加称为准确率。

## 俄罗斯与服务域名

RU从当轮可用全球位置估计提取，结合RIPE登记、RIS/RouteViews/geofeed对照，独立大区ID由版本化 `config/regions.json` 定义；欧洲/亚洲不能重复包含RU。`.ru`、俄罗斯登记ASN、访问限制、WARP出口均不单独证明服务身份或物理位置。IP覆盖/冲突与域名覆盖/混合身份分别统计。

[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)为主要基础之一；固定commit，解析include、属性、精确、后缀、keyword、regexp原义。Sukka实际生成库为[SukkaLab/ruleset.skk.moe](https://github.com/SukkaLab/ruleset.skk.moe)。[ACL4SSR](https://github.com/ACL4SSR/ACL4SSR)与blackmatrix7仅选择V2Ray/Clash/Mihomo/Surge相关资料；同规则的格式、镜像及生成库不作独立多票，参考新增项不盲并集。UA、MITM、rewrite模块不接入。

[Microsoft365官方机器目录](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service)含serviceArea、category、required及端点范围。只处理相应服务，不把整个Microsoft/CDN/CA视作Office。GUID是下载客户端关联标识而非密钥，配置可换为使用方自己的GUID；接口429不轮换GUID绕过。

## 快照与重放

1. 下载在计算前完成。GitHub先把branch固定为40位commit，再抓同一commit的少量文件或DLC归档。HTTP固定已得字节，逐块SHA256，记录实际ETag/Last-Modified（如有）；无上游版本时以内容摘要命名，不伪造日期。
2. 解压拒绝绝对路径、`..`、链接、特殊文件和重复覆盖，限制下载/展开体积及成员数。跨源HTTPS重定向剥除Authorization/Cookie，不降级HTTP。环境凭据及原始异常URL不写日志或产物。
3. 最后写 `snapshot.json`，非空目录不允许隐式刷新。构建前复核路径、长度和树摘要。原始厂商资料不进入公开release或Actions artifact。
4. `fetched_at`只是获取时间，不是发布日期或精度；只保留于输入快照，公开版本稳定身份不因重新获取相同字节的时间而改变。
5. 独立可完成的来源继续处理，缺源不伪称达到五源或准确性目标。官方访问配额、月度建议及限速优先，不换账户/改GUID/爬登录页绕过。
