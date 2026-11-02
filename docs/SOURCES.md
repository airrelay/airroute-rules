# 场景、来源与构建方法

本项目使用 Rust 构建规则集。实现结构见 [ARCHITECTURE](ARCHITECTURE.md)，任务与观测复用见 [SCHEDULING](SCHEDULING.md)，质量约束见 [RULESET-AUDIT](RULESET-AUDIT.md)。本文说明公开来源的用途、选择边界和许可，不记录部署环境或历史运行快照。

## 中国大陆直连

`region/cn.list` 回答“哪些国内服务域名和大陆 IP 范围适合国内直连场景”。域名优先、IP 兜底；地理 IP 数据不能代替域名覆盖，尤其 DNS 尚未解析、CDN 返回不同地址或多个产品共享地址时。

| 来源 | 用途 | 处理边界 |
|---|---|---|
| [DLC cn](https://github.com/v2fly/domain-list-community/blob/master/data/cn) | 国内服务目录与国内顶级域 | 递归展开 include、属性和 affiliation，保留有类型谓词后清洗；包含 `tld-cn` |
| [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 的 accelerated-domains | 国内中小网站及适合国内 DNS/CDN 的域名 | 转为后缀规则，移除解析器字段，保留域名范围 |
| [ChinaMax_Domain](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt) | 国内聚合域名与指定端点补充 | 前导点表示包含根域的 suffix，无前导点保持 exact；不从其他文件继承进程或共享 ASN |
| [china-operator-ip](https://github.com/gaoyifan/china-operator-ip) 的 china/china6 | 中国网络 IPv4/IPv6 辅助分类 | 按真实区间与地理来源对齐，只作网络提示，不作为物理位置票或单独新增 CN 范围 |

[Loyalsoldier](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/master/.github/workflows/run.yml) 与 [MetaCubeX](https://github.com/MetaCubeX/meta-rules-dat/blob/master/.github/workflows/run.yml) 的构建方法可用于理解原料选择；聚合列表与其上游存在依赖，不当作独立票重复计数。集合以所选原料和有类型谓词去重。

这些来源表达可维护的网络和服务分类，不承诺逐域名实时可达。dnsmasq 列表侧重国内 DNS/加速效果，运营商列表的 BGP 分类与 RIR 登记也不等于逐地址物理位置。境外厂商的部分端点可在国内使用，不足以把其整个根域加入 CN。

## 地区 IP 与 Anycast

地理原料使用 IPLocate 与 DB-IP Lite 的完整 IPv4/IPv6 数据，按国家到地区映射归一化，再对齐精确地址边界。中国大陆地理结果 `cn-geo` 仅是内部标识，作为唯一公开 `region/cn.list` 的 IP 部分；不另行发布 `region/cn-geo.list`。其他地区主要提供 IP 规则，不根据厂商总部或 ccTLD 推导整个厂商的服务域名。

构建先匹配能直接回答事实、范围适用、近期合格且不矛盾的观测；没有适用事实时，独立有效地理来源映射到大区后按严格多数选择，无多数使用 IPLocate、DB-IP 的固定主备顺序。镜像不增加票数，缺失不算反对。有效来源的跨区分歧继续确定性输出并保留待补证记录，不因分歧直接丢弃地址范围。全部地理来源与适用事实均无信息时，明确记录覆盖缺口。

当前采集入口提供 DNS、目标可达性、目标负响应及路径材料，没有可信的目标位置或服务所有权事实导入源。适用事实优先是数据模型的判断顺序，不能表述为已经从 traceroute 生成地理真值。单 IP 观测不能扩大为父前缀，DNS 结果也不能反推永久产品归属。

范围明确的完整高置信度 Anycast 独立分类；高置信度 partial、疑似及粒度过宽的候选保留其范围与不确定性，不扩大 backing prefix，也不阻止已有地理来源的确定性回退。RIS/BGP 描述路由边界和起源，登记国与公共 geofeed 是辅助线索，均不单独证明物理位置。参考 [RIPE RISwhois](https://ris.ripe.net/docs/ris-whois/)、[Anycast Census](https://github.com/ut-dacs/anycast-census)、[geofeed 格式 RFC 8805](https://www.rfc-editor.org/info/rfc8805/) 与 [geofeed 发现 RFC 9632](https://www.rfc-editor.org/info/rfc9632/)。

## 服务分类

能直接对应上游分类的集合使用上游分类加显式成员；没有语义一致的上游大类时，使用明确的产品成员，不用集团总集代替用途。

| 分类 | 主要来源选择 |
|---|---|
| 海外 AI、中国大陆 AI、全部 AI | `category-ai-!cn`、`category-ai-cn` 及对应成员 |
| 开发与分发、容器仓库 | `category-dev`、`category-container` 及明确服务成员 |
| 网盘与同步、即时通信、社交社区 | `category-netdisk-!cn`、`category-communication`、`category-social-media-!cn` 及明确成员 |
| 远程接入、游戏 | `category-remote-control`、`category-games` 及明确服务成员 |
| CDN、学术 | `category-cdn-!cn`、`category-scholar-!cn` 及明确成员 |
| 视频、音乐、播客、会议、邮件、办公、云、操作系统、搜索知识、教育、支付、购物出行 | 配方中明确的产品成员并集 |

分类对继承成员重新清洗，不继承厂商的宽根域例外。例如购物只投影 Amazon 零售域名，不继承 AWS；邮件排除 Proton VPN。云/CDN 表达共享基础设施，不能识别承载其中的具体 App。具体产品规则通常排在这些大类之前。

## 服务商、产品与特殊用途

厂商和产品优先使用 DLC 对应文件，再合并 blackmatrix7 的有类型补充。保留 AirRoute 支持的域名、进程、ASN、源地址、端口等原子谓词；原料没有的类型不凭空添加，客户端缺少相应元数据时也无法保证命中。

没有独立上游产品文件的集合使用显式端点子集。Copilot 不继承 OpenAI 整套产品或共享托管 ASN；Netflix 不继承共享 AWS 地域根域；Google Drive 不继承整个 googleusercontent.com；普通服务默认排除无标签边界关键词和共享遥测根。供应商自有托管命名空间可以表达其平台范围，但例外不会自动传播给购物、AI 等用途分类。

`config/endpoints.references.json` 记录 APNs、WNS、Office、Windows Update、Google Search 的官方依据与复核日期；`config/endpoints.json` 保存选定端点。它们不是自动同步的完整官方放行列表。Google Search 使用精确主机，同主机内的不同 URL 功能不能只靠域名区分。微软官方连通性列表也含共享依赖，不能整份视为 Office 专属身份。

LAN、连通性检查、推送、HTTPDNS、STUN、NTP、下载等按具体用途构建，不隐含 DIRECT/REJECT 动作。LAN 保留实际私网、回环、链路本地、CGNAT/ULA 与本地命名，排除 Fake-IP 和文档地址。APNs 不把 Apple 全部地址当作推送专网；WNS 仅使用设备接收侧端点。

## 候选目标与补充观测

候选发现不参与地理投票：已接受规则中的明确域名经受限 DoH A/AAAA 查询得到 TTL 内候选；[RIPE Atlas 公共测量目录](https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/listing-measurements/)按 ID 游标分页读取，仅在目标落入待证范围时读取[已有 latest 结果](https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/results-and-latest/)，并核对原始时间及实际目的地址响应。自有节点与 Globalping 的已接纳收据增量合并；Globalping 按[官方结果结构](https://github.com/jsdelivr/globalping/blob/master/public/v1/components/schemas.yaml)区分 DNS 候选和目的端响应。不创建 Atlas 测量，不用中间路由器代替目的地址。

可由端点观测补充材料的问题按 BGP 边界内的同质连续范围拆分，每组最多三个固定候选。先保留既有选择，再优先已有 DNS/端点候选；IPv4 缺额允许按稳定 seed 从本组精确范围有限补充，IPv6 只用已知精确目标，缺少时等待候选。不能跨地址洞或更具体路由合并，也不枚举子网。

`sampled-candidate` 只表示地址的选择来源，没有响应时钟或 TTL，不代表地址已响应、位置已证实或前缀已核实。真实回传只补充该精确 IP 的响应、负响应或路径材料。不可由现有观测回答的纯地理来源分歧不安排主动任务。共享任务按目标、方法和必要视角去重，有限尝试与未知提交防重规则见 [SCHEDULING](SCHEDULING.md)。

## 构建与导出

Rust 完成下载、DLC include/属性/affiliation 展开、IDNA/CIDR 规范化、集合并集与去重。每日构建固定来源、已有观测和判断规则；新观测由下一次构建使用，不逐条触发重建。

最终导出才做等价压缩：完全相同规则去重；域名谓词仅在可证明被最终保留的后缀、通配符或关键词完整覆盖时删除；正则需从语法树证明覆盖关系。不会发明更宽的根域，不作通用正则语言合并。IP 聚合须在方向、类型、地址族与修饰符一致时保持精确区间等价，不填补地址洞，优化应当幂等。

含逗号的受支持正则只作语言等价转换；不支持的表达式、环视、反向引用或无法表示的 AND/NOT 结构会导致构建失败，不静默丢弃或改成 OR。格式与兼容性门禁不能代替所有 AirRoute 版本和平台的完整运行验证。

每个集合导出一个 classical `.list` 文件，另输出根目录 `ip-library.csv`；CSV 与规则一起参与不可变版本哈希和校验，不携带原始来源或观测证据。完整目录通过校验才激活和进入发布队列；无变化时跳过重复提交。来源缓存、临时目录、原始观测与维护任务不进入公开产物。

## 来源与许可

以下许可与署名来自当前生成索引的来源声明；分发衍生数据时仍需保留对应条件，并以实际采用的上游版本为准。

| 来源 | 许可或公开依据 |
|---|---|
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | MIT |
| [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) | GPL-2.0 |
| [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) | WTFPL |
| [china-operator-ip](https://github.com/gaoyifan/china-operator-ip) | MIT |
| [IPLocate.io](https://www.iplocate.io) | CC BY-SA 4.0；地区映射、选择及聚合仍保留署名与衍生许可 |
| [DB-IP Lite](https://db-ip.com/db/download/ip-to-country-lite) | CC BY 4.0 |
| [Mozilla PSL](https://publicsuffix.org/list/) | MPL-2.0 |
| [Anycast Census / LACeS](https://github.com/ut-dacs/anycast-census) | 许可见上游 |

辅助依据包括 [Cloudflare 官方地址](https://www.cloudflare.com/ips/)、[Google Public DNS](https://developers.google.com/speed/public-dns/docs/isp)、IANA [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) / [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) 特殊地址表、[RIPE RIS](https://ris.ripe.net/docs/ris-whois/)、[geofeed-finder](https://github.com/massimocandela/geofeed-finder) 与 [UN M49](https://unstats.un.org/unsd/methodology/m49/overview/)。BGP、geofeed 和候选地址的使用不提升其事实权限。

官方端点参考：[Apple 推送](https://support.apple.com/en-us/101555)、[Microsoft 推送](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/firewall-allowlist-config)、[Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges)、[Windows Update](https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/windows-update-issues-troubleshooting) 与 [Google 搜索域名调整](https://blog.google/products-and-platforms/products/search/country-code-top-level-domains/)。这些引用解释所选范围，不承诺完整应用鉴别或所有产品连通性。
