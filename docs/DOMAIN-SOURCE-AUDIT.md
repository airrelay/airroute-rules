# 域名来源与选择器核查

核验日期：2026-11-03。此表描述域名的服务、市场及分流用途，不推断服务器的物理位置。所有获取都是固定版本的公开文件下载；没有逐目标 DNS / TLS / HTTP 测量。来源配置见 [sources.json](../config/sources.json)，实际 selector 与例外见 [regional-domains.json](../config/regional-domains.json)。

| 来源与载体 | 实际用途 / 获取状态 | 血缘和边界 |
| --- | --- | --- |
| DLC `data/geolocation-cn`、`category-ru` 与其 include | 原始主分类，固定 commit 后展开 include 和属性；有明确分类的成员可直接进入对应集合 | 一个 DLC 血缘。RU 具名子分类保留，`tld-ru` / `tld-su` 等全公共后缀快捷项单独排除，不能因此丢整个聚合 |
| blackmatrix `rule/Surge/China/China.list` + `China_Domain.list` | 两文件共同消费；伴随文件含 3,689 个已解析域名谓词，原配置缺失此文件会实际漏收 | 上游说明要求主体与 Domain 文件共同使用；不能把共享头部统计当作每个文件的内容统计 |
| blackmatrix `rule/Surge/ChinaMax/ChinaMax.list` + `ChinaMax_Domain.list` | 成熟中国市场/分流分类直接输入；Domain 文件实际解析 110,427 个谓词 | 既有身份目录或多票不是门槛；按明确类型、过宽公共后缀、共享基础设施父域及冲突作定向纠错，不无条件复制所有类型 |
| ACL4SSR `Clash/ChinaDomain.list`、`ChinaMedia.list` | 635 与 37 个已解析谓词；后者另有 1 项不可表达 | 中国访问/市场用途，不等同公司国籍；含精确第三方依赖。与 ChinaMax 等存在已知共同上游，不增加独立票 |
| Sukka `List/non_ip/domestic.conf`、`domestic_cdn.conf` | 869 与 19 个已解析谓词，另有 4 与 1 项不可表达 | 主张大陆可用和国内服务 CDN 用途；CDN 是 domestic 的子集。没有选择 generic `direct.conf` 来推定中国身份 |
| 旧客户端 `region/cn.list` | 固定回归基线：112,523 域名谓词、23,682 IP 谓词；不作为无限制新规则来源 | 每行原始上游未知，如实标记；全球产品、第三方依赖与旧错误不能为了恢复条数全部继承 |

以上数字是冻结输入的解析谓词数，既不是新增网站数，也不是最终输出数或准确率。精确与后缀覆盖应按匹配语义比较，不能仅作文本差集。DLC 的具体版本与最终接纳量以当轮 snapshot 和生成报告为准；其他三条地域库缺凭据不影响这些公开域名来源。

## ChinaMax 组成与定向例外

固定版 [README](https://github.com/blackmatrix7/ios_rule_script/blob/0b6897dc17e0c513d25449c935a9694818e32f0c/rule/Surge/ChinaMax/README.md) 将 ChinaMax 定义为 China、ChinaIPs、Mainland 等国内网站/IP 合集，排除 Advertising；同时标注实验性规则。公开上游包括 ACL4SSR、LM-Firefly、blackmatrix 自有分类、Hackl0us、Loyalsoldier、GeQ1an、sve1r 等。列表格式转换、同一来源的多个产品以及这些已知衍生不能当作独立多票，也不虚构逐行血缘。

具体例外必须有边界，不能反向变成逐条身份审核门槛：

- 主体实际含公共后缀 `.cn` / `.ms` 和品牌 TLD；公共后缀与品牌后缀不能混为同类，公共 TLD 快捷覆盖不得悄然等于所有该后缀服务的市场身份。
- Domain 文件实际含共享云父域 `.aliyuncs.com` / `.myqcloud.com`。它们并不证明所有客户都是大陆服务；有依据的精确客户端点仍可保留，不能连带拒绝所有新域名。
- 主体实际有 keyword、IP-ASN、进程与 UA 类型。保留 Core 可等价表达的域名语义；不支持类型隔离，不扁平化复合条件，不用一个不支持类型否决整个文件。
- 上游明确排除 Advertising，不虚称已完成所有广告/遥测识别；只纠正实际确认的分类错误，域名随机外观或其他名单缺失不是反证。
- Sukka 的 `7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe` 是每份生成文件的发布者哨兵，不是业务端点，作精确排除；不扩张到整家发布者域名。

Sukka [生成器](https://github.com/SukkaW/Surge/blob/master/Build/build-domestic-direct-lan-ruleset-dns-mapping-module.ts)把维护的 DOMESTICS、domestic 配置和 domestic_cdn 子集合并，generic direct 单独输出。生成文件声明 AGPL-3.0；同时仍需遵守继承材料的权利和条款，不把“免费可下载”当作无条件分发授权。

## 俄罗斯补充来源的实际核查

blackmatrix 固定版的具名 Yandex、VK、Mailru 三文件共 44 个域名谓词，已被当前 DLC `yandex` / `mailru-group` 的匹配语义覆盖。其 README 还明确引自 LM-Firefly 等列表，因此没有为制造源数量而再订阅零新增镜像。ACL4SSR 和 Sukka 的已核目录未发现可靠的独立 RU 聚合。

[runetfreedom/russia-domains-list](https://github.com/runetfreedom/russia-domains-list)的本地可用性清单与 [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains)的封锁/地理限制绕行清单不等同俄罗斯服务身份；核查时未见可支持本项目公开派生的明确许可，未自动导入。俄罗斯当前扩展来自恢复 DLC 原有具名类别，而不是宣称新增多个独立俄罗斯来源。

## 固定输入与健康状态

本次有界获取仅选择 blackmatrix、ACL4SSR、Sukka、旧 CN 四源，均 available，完整字节/树摘要已通过快照校验，没有下载全套 Geo 库。版本分别为 `0b6897dc17e0c513d25449c935a9694818e32f0c`、`c15bf546085b825afd238e211f750bb7868c7132`、`136f19cc769a2a1f2878e880c4297cbcd3f34b6f`、`20a3b237005292e60b62603e934b3972348366b4`。

旧 CN 原文件为 3,923,114 字节，SHA-256 `9e763ebd67e35b23ed8c41bc8a9cb40556e248ee18f2115a6137298b09deb883`。snapshot 内 `sha256` 为包含路径和长度的树摘要，不能混为单文件摘要。输入验收位于 `.build/regional-sources/`，不会进入 release；最终规则是否发布以实际工作流和远端 release 为准，本地候选不等于正式发布。

当前域名路径同时消费 China / ChinaMax 主体与 `_Domain`；`domain_only` 不导入其 IP。Core 可表达的 keyword / regex 保留，国家名关键词与 dotless TLD 快捷项定向排除；`gov.cn` / `edu.cn` 具名政教命名空间保留。大陆排除依据 DLC 具名服务的完整覆盖；大陆访问可用性与全球产品的实际相交不自动删除全球父域，逐项报告且不指定顺序。无法证明不相交的 keyword / regex 按组汇总未知模式，不宣称全无重叠，不新增逐条证据平台。
