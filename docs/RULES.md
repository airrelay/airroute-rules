# AirRoute 规则语义与产品边界

本系统只下载公开的既有资料。规则生成不查询目标 DNS、不建立 TLS/HTTP 目标连接，不从 CA、共享 CDN、注册地、TLD 或可达性推断产品身份。

## 可维护的产品目录

`config/products.json` 是域名产品的权威目录，维护 12 个服务商、38 个独立服务、21 个用途类别及原流媒体聚合视图。`includes` 定义服务到类别的包含关系，按依赖顺序合并后执行同一份 CN 排除与无损压缩；循环和未知引用直接失败，不能只更新目录标题。`config/catalogue-migration.json` 记录要求中的目标及只读核查到的旧目录项目的保留、归并与缺口。16 个地域由稳定注册表补全，缺少可靠地域域名证据时显式标记，仍使用已验证的地域 IP，而不制造地域域名。

`config/special.json` 单独定义特殊地址/端点和 DNS 地址模式例外；它们不是海外服务身份，不套用 CN/海外互斥逻辑，执行各自的用途与安全验证，详见 [SPECIAL.md](SPECIAL.md)。

海外服务商与服务类别是不同用途的可选视图，可能有交集；它们不是互斥的地理分区。中国大陆只有 `region/cn` 一个公开集合。DLC `geolocation-cn`、具名大陆类别、China/ChinaMax 主体与 `_Domain` 伴随文件、ACL4SSR、Sukka 国内分类以及微软中国云明确端点均可按成熟分类直接贡献域名。新候选不必先被已有身份目录覆盖，不要求其他列表重复收录；来源血缘不作为虚构的独立票数。

域名 CN 表达市场与分流用途，不等于服务器位置；`@cn` 也可能描述境外服务的大陆接入端点。地域 IP 仍来自与 Geo 库相同的清洗结果，不盲并域名源附带的 IP。普通域名规则保留 Core 支持的 keyword / regex；仅 `cn`、`china`、`ru`、`russia` 等国家名关键词、dotless TLD 快捷项及明确过宽范围作定向排除。`gov.cn`、`edu.cn` 是具名政教命名空间，保留其用途范围，不按整个 `.cn` 的快捷项一并删除。

大陆排除使用 DLC 具名大陆服务的语义覆盖，而不是把所有大陆可用域名当作大陆独有身份：一个其他集合的谓词被具名大陆范围完整覆盖时排除；只有子端点或访问可用性相交时，不整体删掉国际产品的父域。正向 `.list` 无法作安全减集的实际交集逐项报告，保留或暂缓的范围与原因可查，不隐含优先级、NOT 或出口策略。对于一般 keyword / regex 与无限后缀语言无法证明不相交的情况，保留原谓词，按组汇总未知模式交集和有界样例；不声称已经证明互斥，也不建立逐条证据平台。具体混合市场声明见 [地域域名策略](REGIONAL-DOMAINS.md)。

`region/ru` 与 `category/ru-services` 使用 DLC `category-ru` 的具名银行、机构、运营商、产品和其他子类别；单独跳过 `tld-ru` / `tld-su` 等公共后缀快捷子树，不能因此丢弃整个聚合。俄罗斯服务可保留在其他有实际用途的类别中；两个视图的交集是用途重叠，不是新增独立来源。其地域 IP 与 Geo 库相同，不将集团的所有全球域名或 ASN 注册国当作俄罗斯物理端点。

## 上游语义

以 DLC 源码目录而非其二进制成品为基础，固定 Git 提交后解析：

| 输入 | 输出/处理 |
| --- | --- |
| DLC `domain:example.com` 或无前缀 | `DOMAIN-SUFFIX,example.com`，包含根域和子域 |
| DLC `full:example.com` | `DOMAIN,example.com`，仅精确域名 |
| DLC `keyword:example` | `DOMAIN-KEYWORD,example`；保留主分类语义，国家名快捷关键词单独排除 |
| DLC `regexp:...` | 能通过公共语法验证且 Core CSV 可无损表达时保留；否则隔离 |
| `include:list @cn @-ads` | 仅包含带 `cn` 且不带 `ads` 的原条目；属性是筛选条件，不是为条目加标签 |
| `&list` affiliation | 加入对应目标列表，即使该列表没有独立文件；属性继续保留 |
| V2Ray 配置无前缀 domain 字符串 | 按原始配置含义解释为关键词，不能套用 DLC 默认后缀语义 |
| Clash/Mihomo domain payload `+.example.com` | 根域与子域，转换为 `DOMAIN-SUFFIX` |
| Clash/Mihomo domain payload `*.example.com` | 仅子域，转换为等价锚定正则，不能扩大为包含根域；无法证明的跨市场交集按组报告 |
| Surge DOMAIN-SET `.example.com` / `example.com` | 分别为后缀 / 精确域名 |
| 第三方 `DOMAIN-WILDCARD` | 方言不明确时隔离，不能猜测通配符是否包含根域 |
| IP 前缀带 `no-resolve` | 输入可识别；输出统一不带 `no-resolve`，不推断客户端最终出口 |
| AND / OR / NOT、嵌套、V2Ray 额外字段条件 | 整个谓词隔离，不抽出内部域名以免扩大匹配 |
| UA、URL、MITM、脚本、子规则引用及未知类型 | 隔离，不生成相关功能或其他客户端格式 |

Core 的 `DOMAIN-WILDCARD,*.example.com` 当前优化分支包含根域，因此不能直接搬运只表示子域的上游星号。DLC 使用 Go 正则，Core 使用 Rust regex；Python 校验器仅接受已知公共子集，反向引用、前后查找、逗号分隔歧义及不能验证的语法明确隔离。Core 当前还会对正则执行 ASCII 小写，因此任何会被该过程改变的正则均被隔离，包括 `\D`、`\S`、`\W` 等大写转义、大小写敏感的字面量及 `[A-Z]` 字符类；不能将其改为更宽的匹配。无法表达的规则不会悄悄缩减成更宽的后缀。

第三方只读取 V2Ray/Clash/Mihomo/Surge 文件。可靠的具名服务和成熟地域分类可直接贡献规则；ChinaMax 不再通过 `corroborated` 要求先命中旧身份目录。`domain_only` 只取域名谓词，不把第三方 IP 混入 Geo；`bounded_service`、`owned_roots` 等仅服务于确有范围约束的具体服务选择器，不是给所有新域名设置门槛。共享云/CDN 的整个父域可精确排除，有依据的精确或有界的客户端点保留。与其他名单未精确匹配不是反证；共同上游不计独立票。UA、进程、无法等价表达的复合条件仍隔离，不能因文件中含这些类型而丢掉其全部域名。
Microsoft 365 的官方机器可读端点只通过显式 `microsoft365` JSON 适配器接入；服务区域字段决定产品范围，域名通配符不扩大到根域。单条不能表达的模板按记录 ID、数组位置和原因隔离，不使整个来源的有效端点失效；一般通配符仍须通过匹配范围及跨市场检查，不能凭官方来源跳过产品边界。资料缺失只报告缺失，不临时浏览网页补数据或主动拨测。微软连通性清单中的证书校验/共享依赖不自动取得微软身份；DigiCert、GlobalSign等依赖域明确排除。GitHub官方meta中的泛用云提供商通配符也不自动取得GitHub或Copilot身份。Telegram官方CIDR目录进入Telegram服务集合及包含该服务的即时通信类别，经过双栈无损合并；不作为地域证据，也不扩展到所属整个ASN。

## 无损去重与可追溯性

规范化包含 ASCII 小写、合法 ASCII/已有 Punycode 域名、IP 网络地址归一化。原始非 ASCII 域名明确隔离，等待两端约定 IDNA 映射；不使用 Python 标准库 IDNA2003 将 `straße.de` 改写成不同的 `strasse.de`，也不宣称已完整支持 Unicode 域名。只有能证明包含关系的项目才删除：后缀覆盖同域精确项/更长后缀，短关键词覆盖包含它的更长关键词；关键词覆盖其字面量本身即包含关键词的精确项/后缀。正则不做猜测包含；额外只识别规范严格子域正则：可删除被祖先后缀覆盖的正则，也可删除其已经覆盖的子域精确项/更窄后缀；该正则不包含根域自身，不能借合并扩大到根域。IPv4/IPv6 分别使用 CIDR 并集无损折叠，标签比较使用点边界，`badexample.com` 不被 `example.com` 覆盖。

报告保留来源版本、selector、输入与接纳、覆盖去重、拒绝原因、有界样例及实际大陆交集处理记录。未知 keyword / regex 交集按组汇总，不制造逐条诊断库。压缩只是表示优化，不改变匹配集合。源文件格式、镜像和发行者数均不能被当成独立证据票数。

本仓库测试验证解析、属性/包含/affiliation、复合谓词隔离、通配符边界、CN 排除、原始到压缩等价及第三方共享基础设施隔离。客户端 Core 的完整规则编译与运行互操作仍须在客户端仓库消费发布样例验证；读取其源码不等于已修改或发布客户端。

## 核查入口

- [DLC 官方源码语法](https://github.com/v2fly/domain-list-community#structure-of-data)
- [Sukka 官方源码、生成格式与许可](https://github.com/SukkaW/Surge)
- [blackmatrix7 OpenAI Surge 来源](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Surge/OpenAI/OpenAI.list)
- [ACL4SSR OpenAI Clash 来源](https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/Ruleset/OpenAi.list)

这些链接说明来源及字段语义；实际构建必须使用获取阶段固定的版本和摘要，不能在解析过程中读取移动分支。
