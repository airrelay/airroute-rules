# AirRoute 规则语义与产品边界

本系统只下载公开的既有资料。规则生成不查询目标 DNS、不建立 TLS/HTTP 目标连接，不从 CA、共享 CDN、注册地、TLD 或可达性推断产品身份。

## 可维护的产品目录

`config/products.json` 是域名产品的权威目录。集合仅包含少数有独立分流价值的服务商/服务，以及 AI、开发、游戏、媒体、流媒体等实用类别，不按每个上游文件生成一个集合。

海外服务商与服务类别是不同用途的可选视图，可能有交集；它们不是互斥的地理分区。本版强制保证的是大陆身份集合与海外集合的排除关系。

中国大陆只有 `region/cn` 一个公开集合。域名材料以 DLC 的 `geolocation-cn` 为主，补充具名大陆身份类别及微软中国云官方目录中的区域端点，不用兼容入口 `cn`，因为后者包含整个 `.cn` TLD；DLC 中的 `@!cn` 明确排除，`@cn` 可描述境外服务的大陆接入端点，并不把其全球服务都划为大陆。地域 IP 来自与 Geo 库相同的清洗结果，不采用第三方规则库 IP 的盲目并集。

其他服务商和类别必须与已接纳的大陆域名集合排除：精确域名/后缀有标签边界交集时，删除整个重叠的海外谓词并报告。例如大陆包含 `DOMAIN,cn.mixed.example`，海外的 `DOMAIN-SUFFIX,mixed.example` 无法在普通 `.list` 中减掉该点，因此海外后缀整体隔离，不引入隐式顺序或 `NOT`。任意关键词、一般正则与大陆集合无法证明无交集时也隔离；仅对适配器生成的规范严格子域形式 `^.+\.example\.com$` 做小范围精确识别，用相同的域名索引核验交集：大陆精确根域自身不属于该形式，但大陆子域或覆盖它的大陆后缀属于交集。解析器保留原始谓词，不以删除条件的方式“修复”。这会牺牲部分模糊覆盖，报告中明确计数，不把未知伪装成海外。

`category/ru-services` 是有明确俄罗斯服务身份的域名材料，不等于服务器在俄罗斯。只引用 Yandex、Mail.ru 等有明确上游身份的条目，不使用包含 `tld-ru` 的 `category-ru`。`region/ru` 在相同Geo IP资料之前附上明确的当地银行、政府、教育、零售、媒体等身份类别；它不包含整个 `.ru`，也不把跨国集团的所有域名都认作俄罗斯端点。保留原 `category/ru-services` 下载路径，两个视图可重叠但职责范围不同；全局覆盖对比去除跨产品重复，不把复制视图计为新增覆盖。其他部分大区同样只接纳显式机构/服务身份清单，其IP部分与Geo库完全一致。

## 上游语义

以 DLC 源码目录而非其二进制成品为基础，固定 Git 提交后解析：

| 输入 | 输出/处理 |
| --- | --- |
| DLC `domain:example.com` 或无前缀 | `DOMAIN-SUFFIX,example.com`，包含根域和子域 |
| DLC `full:example.com` | `DOMAIN,example.com`，仅精确域名 |
| DLC `keyword:example` | `DOMAIN-KEYWORD,example`；产品身份不足或大陆无法排除时隔离 |
| DLC `regexp:...` | 能通过公共语法验证且 Core CSV 可无损表达时保留；否则隔离 |
| `include:list @cn @-ads` | 仅包含带 `cn` 且不带 `ads` 的原条目；属性是筛选条件，不是为条目加标签 |
| `&list` affiliation | 加入对应目标列表，即使该列表没有独立文件；属性继续保留 |
| V2Ray 配置无前缀 domain 字符串 | 按原始配置含义解释为关键词，不能套用 DLC 默认后缀语义 |
| Clash/Mihomo domain payload `+.example.com` | 根域与子域，转换为 `DOMAIN-SUFFIX` |
| Clash/Mihomo domain payload `*.example.com` | 仅子域，转换为等价锚定正则，不能扩大为包含根域；若产品排除条件无法证明则隔离 |
| Surge DOMAIN-SET `.example.com` / `example.com` | 分别为后缀 / 精确域名 |
| 第三方 `DOMAIN-WILDCARD` | 方言不明确时隔离，不能猜测通配符是否包含根域 |
| IP 前缀带 `no-resolve` | 输入可识别；输出统一不带 `no-resolve`，不推断客户端最终出口 |
| AND / OR / NOT、嵌套、V2Ray 额外字段条件 | 整个谓词隔离，不抽出内部域名以免扩大匹配 |
| UA、URL、MITM、脚本、子规则引用及未知类型 | 隔离，不生成相关功能或其他客户端格式 |

Core 的 `DOMAIN-WILDCARD,*.example.com` 当前优化分支包含根域，因此不能直接搬运只表示子域的上游星号。DLC 使用 Go 正则，Core 使用 Rust regex；Python 校验器仅接受已知公共子集，反向引用、前后查找、逗号分隔歧义及不能验证的语法明确隔离。Core 当前还会对正则执行 ASCII 小写，因此任何会被该过程改变的正则均被隔离，包括 `\D`、`\S`、`\W` 等大写转义、大小写敏感的字面量及 `[A-Z]` 字符类；不能将其改为更宽的匹配。无法表达的规则不会悄悄缩减成更宽的后缀。

第三方只读取 V2Ray/Clash/Mihomo/Surge 文件。本配置将 blackmatrix7、ACL4SSR、Sukka 文件作为身份交叉参考：通过后缀/精确域名/规范严格子域的语言包含关系比对。`corroborated`只接纳被配置的具名身份目录完整包含的候选；过宽父域最多缩为目录已证明的子项，不接纳整个父域。无证明候选按原因完整计数并保留有界样例，原始输入仍在固定快照；匹配文本不同不等于缺口。共同上游尚未逐行证明，不将发布者数或不同格式当作独立票数。以 OpenAI 为例，上游文件可能同时包含支付、CA、共享分析平台、整段 ASN；这些不是 OpenAI 独有身份，不能直接并入产品。

Microsoft 365 的官方机器可读端点只通过显式 `microsoft365` JSON 适配器接入；服务区域字段决定产品范围，域名通配符不扩大到根域。单条不能表达的模板按记录 ID、数组位置和原因隔离，不使整个来源的有效端点失效；一般通配符仍须通过大陆排除条件，不能凭官方来源跳过产品边界。资料缺失只报告缺失，不临时浏览网页补数据或主动拨测。微软连通性清单中的证书校验/共享依赖不自动取得微软身份；DigiCert、GlobalSign等依赖域明确排除。GitHub官方meta中的泛用云提供商通配符也不自动取得GitHub或Copilot身份。Telegram官方CIDR目录仅进入Telegram服务集合，经过双栈无损合并；不作为地域证据，也不扩展到所属整个ASN。

## 无损去重与可追溯性

规范化包含 ASCII 小写、合法 ASCII/已有 Punycode 域名、IP 网络地址归一化。原始非 ASCII 域名明确隔离，等待两端约定 IDNA 映射；不使用 Python 标准库 IDNA2003 将 `straße.de` 改写成不同的 `strasse.de`，也不宣称已完整支持 Unicode 域名。只有能证明包含关系的项目才删除：后缀覆盖同域精确项/更长后缀，短关键词覆盖包含它的更长关键词；关键词覆盖其字面量本身即包含关键词的精确项/后缀。正则不做猜测包含；额外只识别规范严格子域正则：可删除被祖先后缀覆盖的正则，也可删除其已经覆盖的子域精确项/更窄后缀；该正则不包含根域自身，不能借合并扩大到根域。IPv4/IPv6 分别使用 CIDR 并集无损折叠，标签比较使用点边界，`badexample.com` 不被 `example.com` 覆盖。

报告同时保留压缩前来源、文件行号、属性、不可用 selector、隔离原因和大陆交集删除记录。压缩只是表示优化，不改变匹配集合。源文件格式、镜像和发行者数均不能被当成独立证据票数。

本仓库测试验证解析、属性/包含/affiliation、复合谓词隔离、通配符边界、CN 排除、原始到压缩等价及第三方共享基础设施隔离。客户端 Core 的完整规则编译与运行互操作仍须在客户端仓库消费发布样例验证；读取其源码不等于已修改或发布客户端。

## 核查入口

- [DLC 官方源码语法](https://github.com/v2fly/domain-list-community#structure-of-data)
- [Sukka 官方源码、生成格式与许可](https://github.com/SukkaW/Surge)
- [blackmatrix7 OpenAI Surge 来源](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Surge/OpenAI/OpenAI.list)
- [ACL4SSR OpenAI Clash 来源](https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/Ruleset/OpenAi.list)

这些链接说明来源及字段语义；实际构建必须使用获取阶段固定的版本和摘要，不能在解析过程中读取移动分支。
