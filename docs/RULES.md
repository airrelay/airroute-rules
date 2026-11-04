# AirRoute 规则语义与产品目录

规则来自成熟上游的明确分类与机器可读端点。本仓库做采集、展开、格式转换、清洗、合并与输出，不建立逐条域名身份核验系统，不要求 RDAP、CT、厂商根域或多源投票作为准入条件。

## 产品目录

`config/products.json` 定义最终集合与 `includes` 组合；`config/regional-domains.json` 定义中国大陆上游选择，`config/special.json` 定义特殊用途。产品仅有四个顶层分类：

- `region`：除 `region/cn-domain` 外全部是 IP；CN IP 独立为 `region/cn-ip`。
- `category`：用途类别，允许成员与其他类别或地域集合重叠。
- `provider`：服务商及必要单项服务。单项服务的规则不能因为目录迁移扩大为整个公司的范围。
- `special`：LAN、特殊用途、单份 RealIP 和 ASN 数据库。

原 `service/<name>` 迁至 `provider/<name>`，原 RealIP 两份列表合并为 `special/realip.list`，没有 `service` / `dns` 客户端目录。地域以既有 16 大区为限，不添加国家细分类。目录迁移与客户端所需改动见 [PUBLISHING](PUBLISHING.md) 和 [SPECIAL](SPECIAL.md)。

中国大陆服务继续属于其实际用途类别或服务集合。CN 与全球 AI、开发、媒体等可以相交；“不单独建设中国 AI 一类产品”不表示删掉全球 AI 中的中国成员。没有 CN 差集、`-cn` / `!cn` 的隐性全局过滤，也不声称这些用途视图互斥。

## 上游转换

| 上游语义 | AirRoute 输出或处理 |
| --- | --- |
| DLC 默认或 `domain:example.com` | `DOMAIN-SUFFIX,example.com`，根域和子域 |
| DLC `full:example.com` | `DOMAIN,example.com`，仅精确域名 |
| DLC `keyword:` / `regexp:` | 保持关键词/正则语义，须由 Core 可等价表达 |
| DLC `include` 与属性、affiliation | 按源语义展开；文件格式或镜像不是新的独立来源 |
| Clash/Mihomo `+.example.com` | 根域与子域后缀 |
| 仅子域的 `*.example.com` | 可表达时使用等价锚定正则，不扩大成包含根域的后缀 |
| Surge DOMAIN-SET `.example.com` / `example.com` | 分别为后缀 / 精确域名 |
| IP CIDR | 规范化网络地址，双栈分别合并，不输出 `no-resolve`，上游显式标志转换时去除 |
| AND / NOT / 嵌套或未知方言 | 无法等价表示时整条记录原因，不拆成更宽的 OR |
| `PROCESS-NAME` / `IP-ASN` | Core 支持的非 CIDR 谓词保留；去除上游 `no-resolve` 标志，不扩展成完整 ASN 或其他谓词 |
| UA、MITM、脚本等不支持类型 | 记录来源、类型、数量和原因，不生成相关功能 |

只引用上游 V2Ray、Clash/Mihomo、Surge 等文件作为输入，不生成其他 App 格式。Core 的 CSV 规则不能无损表示带逗号的 payload，Go/Python/Rust 的正则方言也并不等价；不兼容语法保留拒绝记录，不猜测改写。非法域名和未约定的 Unicode 映射不能靠 IDNA2003 悄悄变成别的名称；合法单段顶级域名不因“没有点”被一律删除。

Microsoft 365 中国目录按其官方服务范围接入，不要求所有域名以 `.cn` 结尾。共享 CDN、云平台端点、CA 或其他连接依赖保留上游的实际范围与来源，不能仅因不属于自定义厂商根域或缺少独占证明而删除，也不因此宣称共享设施专属于该服务。服务来源中的 IP 不因 `domain_only` 或“独占性未知”被统一丢弃，但它们不成为地域位置证据，不扩展到整个 ASN。

## 无损去重及明确排除

规范化包括合法 ASCII/Punycode 域名小写和 IP 网络地址规范化。所有输出不携带 `no-resolve`，包括上游显式标志；这项转换在记录中注明。删除重复或覆盖项必须能证明匹配集合不变：后缀覆盖其精确域名或更长后缀，关键词覆盖确有包含关系的字面量，CIDR 并集无损折叠；`badexample.com` 不被 `example.com` 覆盖。正则不做猜测包含，也不随意放宽范围。

`exclude_roots` 等具体排除只在能证明被排除范围覆盖该规则时生效。无法证明正则相交不等于已证明相交，不能据此删除。上游未收录另一个域名只表示信息缺失，不构成反证。配置例外应有具体语义，不能重新变成厂商根域、置信分或人工审核平台。

原始条目、展开条目、接纳、不可表达、覆盖去重和最终规则分开记录；成员跨集合重叠与同源引用不能相加成净覆盖或独立证据。反查见 [BUILD_RECORDS](BUILD_RECORDS.md)，来源及 CN/RU 边界见 [SOURCES](SOURCES.md) 与 [REGIONAL-DOMAINS](REGIONAL-DOMAINS.md)。

客户端 Core 的完整编译、订阅导入和运行接入需要在客户端另行验证。本仓库只输出匹配数据，不决定最终 DIRECT/PROXY 或解析器。
