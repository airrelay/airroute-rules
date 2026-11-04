# 数据来源、访问要求与事实边界

权威注册表为 [`config/sources.json`](../config/sources.json)，地域顺序在 [`config/geo-policy.json`](../config/geo-policy.json)，产品组合在 [`config/products.json`](../config/products.json)、[`config/regional-domains.json`](../config/regional-domains.json) 与 [`config/special.json`](../config/special.json)。这是现有公开资料的批量下载系统，没有目标 DNS/TLS/HTTP、ICMP、Globalping、探测节点或逐目标 WHOIS 查询。

下表描述既有接入格式与访问条件（外部条件最后核查于 2026-11-03）；本次没有凭空宣称供应商接口发生变化。当轮能否取得、实际版本、字段及解析数量以构建记录为准。

## 五条地域发布链

| 来源 | 接入格式与地址族 | 访问与更新 | 字段语义 |
| --- | --- | --- | --- |
| [MaxMind GeoLite Country](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) | Country CSV ZIP，IPv4/IPv6 Blocks 与 Locations | 免费账号，`MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`；HTTP Basic；配置按官方免费下载要求执行 | `geoname_id` 关联位置国家；`registered_country_geoname_id` 是注册地，不补作位置 |
| [DB-IP Lite](https://db-ip.com/db/lite.php) | 双栈起止地址 Country CSV gzip | 无令牌、月度完整快照 | 国家位置估计，不推导城市；CC BY 4.0 署名 |
| [IPinfo Lite](https://ipinfo.io/developers/ipinfo-lite-database) | 完整双栈 CSV gzip，不使用公开百行样本充整库 | 免费账号，`IPINFO_TOKEN`；现有发布链每日更新 | `country_code` 为位置估计；ASN 名称/主体另论；CC BY-SA 4.0 |
| [IP2Location LITE DB1](https://lite.ip2location.com/database/db1-ip-country) | IPv4/IPv6 分别下载 ZIP CSV，十进制首末地址 | 免费账号，`IP2LOCATION_TOKEN`；遵守官方免费频率及令牌要求 | 国家位置估计；IPv6 明确按 128 位解析，不按数值大小猜地址族 |
| [IPLocate Country](https://github.com/iplocate/ip-address-databases) | 官方双栈 Country CSV ZIP，固定 Git commit 的载体 | 无令牌、官方公开发布链 | `country_code` 为国家位置估计；不改用 ASN-holder country；CC BY-SA 4.0 |

当前固定顺序为 **IPLocate → MaxMind → DB-IP → IPinfo → IP2Location**。IPLocate 是必需主源；某段无有效地域结果时才向后补缺。主源整库失败不静默替换。可选来源缺凭据、未选择、失败或禁用不是一票“国外”，也不伪称五源成功。来源冲突保存其他原始值及范围，不删除有效主源结果。

五家有不同发行链，不代表统计独立；同源镜像、格式转换及已知衍生保留血缘，不重复计为独立支持。本策略不使用投票或准确率评分。2026-11-04 的旧运行 [41778397925](https://github.com/airrelay/airroute-rules/actions/runs/41778397925) 曾实际取得并解析五家双栈输入，但它使用旧融合策略且未发布，不是本版新策略的验收。

MaxMind 按已确认要求直接参与派生构建，随其他来源记录版本、摘要与贡献，保留署名、CC BY-SA 和 GeoLite EULA 相关义务。免费可下载不等于可无条件再分发；Git 历史及下游删除义务不因开关自动解决，不擅自清理历史。其他来源同样保留各自许可和归因。凭据只来自环境变量或 Actions Secrets，不写入 URL 日志、配置快照或产物。

## BGP、ASN、登记与 geofeed

- [RIPE RISwhois](https://www.ris.ripe.net/docs/ris-whois/)：批量 IPv4/IPv6 origin/prefix 聚合及 peer 数，缺少逐 peer 身份不能伪装为同一 peer。用于当前观察，不证明物理位置。
- [Route Views](https://archive.routeviews.org/)：固定 collector、月份和完整 MRT RIB；保留真实 collector/peer、AS_SET、多起源及更具体前缀。TABLE_DUMP_V2 的合成夹具能力不等于当轮采集器真实提供所有地址族。
- [IPtoASN](https://iptoasn.com/)：官方双栈 TSV gzip，PDDL 1.0；国家字段不用于地域判定，单值衍生映射不能替代全部真实多起源观测。
- [APNIC delegated](https://ftp.apnic.net/stats/apnic/) / [RIPE delegated](https://ftp.ripe.net/pub/stats/ripencc/)：资源分配/登记国、状态和范围，作为注册背景，不转成位置事实。
- [BGP.tools 导出](https://bgp.tools/kb/api)：可选 `table.jsonl`，默认禁用；配置识别用 `BGPTOOLS_USER_AGENT` 并遵守官方频率后才使用，不抓人工页面，不把 Hits 转成置信分。
- RFC 8805 geofeed：运营者自报范围，载体和实际语义单独记录；不是位置真值替代，也不因为一个地址的声明扩张整个网络。
- IANA 特殊 ASN 定义用于标记公开/特殊号码；原始特殊号观测保留，不自动叫上游错误。默认路由和宽范围单独解释，删除了任意 `/8`、`/12` 准入尺寸门槛。

这些资料不能作为 IP 地理主源的伪装备选。RPKI 有效也不证明地域。未见某路由不表示全球已撤销，只有当前固定快照不无限累积旧数据。详细编译成员与观测边界见 [GEO](GEO.md)。

## 中国大陆辅助资料

| 来源 | 既有来源事实 | 当前用途 |
| --- | --- | --- |
| [17mon/china_ip_list](https://github.com/17mon/china_ip_list) | IPIP.NET；含 WHOIS 及未宣告地址；CC BY-NC-SA 4.0 | 配置 `publish_allowed=false`，记录下载状态，不偷偷参与公开融合或辅助计算 |
| [misakaio/chnroutes2](https://github.com/misakaio/chnroutes2) | BGP/运营商路由生成链 | 路由覆盖旁证，不直接并入物理地域结果 |
| [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) | 运营商 ASN/BGP 分类，双栈 ip-lists | 运营商覆盖比较，同生成链不拆成多票 |
| [blackmatrix7 China/ChinaMax](https://github.com/blackmatrix7/ios_rule_script) | 成熟中国分流规则；主体和 Domain 伴随文件需共同读取 | 非 IP 用于 `region/cn-domain`；附带 IP 可按其实际用途在辅助记录中比较，不成为国家位置证据 |
| APNIC、BGP、geofeed | 登记、通告、自报各有语义 | 与最终地域范围对照，不盲目并集扩大大陆 |

中国 IP 与非 IP 结果分开。`region/cn-ip.list` 由地理主源/备选生成，`region/cn-domain.list` 由所选成熟规则生成。全球 AI、游戏、媒体等类别仍保留中国服务成员，CN 和类别重叠允许；不按 CN 差集或 `.cn` 尾缀限制普通服务。

## 域名与服务来源

[DLC](https://github.com/v2fly/domain-list-community) 原始分类、include、属性和 affiliation 是主要基础。[blackmatrix7](https://github.com/blackmatrix7/ios_rule_script)、[ACL4SSR](https://github.com/ACL4SSR/ACL4SSR)、[SukkaLab](https://github.com/SukkaLab/ruleset.skk.moe) 已选 V2Ray/Clash/Mihomo/Surge 材料按原语义直接贡献。不是每条域名都要先命中身份目录、owned_roots 或其他名单；同一上游/格式/镜像不算独立票。

中国选择 China/ChinaMax 主体与 `_Domain`、DLC、ACL 中国用途和 Sukka domestic 等明确材料。保留 Core 支持的关键词、正则及合法顶级域名；不能把所有单段、共享云端点和独占性未知项统一删除。不支持的 UA、MITM、进程及不能等价表示的复合表达式按来源/类型/原因记录，不导致同文件的有效规则连带丢失。

[Microsoft 365 官方 JSON](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service) 以及[中国云资料](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges-21vianet)按实际服务范围接入，不要求中国云所有域名以 `.cn` 结尾；客户端关联 GUID 不是密钥，不通过轮换 GUID 绕过限速。[GitHub meta](https://docs.github.com/en/rest/meta/meta#get-github-meta-information) 和 [Telegram 网络目录](https://core.telegram.org/resources/cidr.txt)保留官方端点/网络实际范围，不扩写整个云平台或 ASN，也不把依赖设施说成独占。

俄罗斯地理 IP 来自相同主源链并独立映射大区。DLC `category-ru` 具名服务及产品用于 `category/ru-services` 和相应 provider/category，不进入 `region/ru.list`。其他地域的服务域名也按实际用途迁移，不用 TLD、ASN 注册国或访问限制证明服务器位置。未接入候选不能写成已经贡献的来源；没有许可或事实语义不适合的清单不额外集成。旧客户端语料只作固定版本语义比较，逐条血缘未知时明确未知。

## LAN、RealIP 与特殊用途

[IANA IPv4 特殊用途](https://www.iana.org/assignments/iana-ipv4-special-registry/)与[IPv6 特殊用途](https://www.iana.org/assignments/iana-ipv6-special-registry/)用于地址含义核对，不把所有特殊地址都当 LAN。DLC private、blackmatrix Lan、ACL 局域网、MetaCubeX private 等作为所选本地命名材料，公共服务出现在其中不自动使整个平台变成局域网。

DLC NTP/STUN 与 [DustinWin fakeip-filter](https://github.com/DustinWin/ruleset_geodata/blob/mihomo-ruleset/fakeip-filter.list) 等已有兼容资料的有效可表达规则合并为单份 `special/realip.list`，记录各自原因和血缘；不再输出基础/扩展两份文件。它只控制 DNS 不返回 FakeIP，不等于直连、指定解析器或路由出口；客户端导入另行对接。

## 固定输入与失败

下载先于计算；GitHub 输入先固定 commit，HTTP 输入记录实际摘要、ETag/Last-Modified（如有）。解压拒绝路径穿越、链接、特殊文件、重复覆盖；跨源重定向剥离授权头，不降级 HTTP。构建复核快照路径、长度与树摘要，原始厂商归档不公开发布。

`fetched_at` 是获取时间，不伪装成发布日期或准确性。来源版本相同不要求重复提交。缺少可选输入及辅助报告如实记录；必需主源缺失、文件损坏和格式错误保留真实失败，不靠历史数量阈值掩盖。失败诊断尽力保存，诊断整理失败不覆盖主错误。查询方法与保留时间见 [BUILD_RECORDS](BUILD_RECORDS.md)。
