# 地域域名：市场与分流用途

地域域名与 Geo/IP 是两条独立的数据链。CN、RU 等域名集合描述社区主库明确归类的服务市场、机构、产品及连接用途，不要求证明服务器物理位置。IP 地域仍按地理资料处理。ASN 注册地、国家后缀、企业国籍，以及另一名单没有收录某域名，都不能单独决定域名归类。

## 简单的生成策略

`config/regional-domains.json` 覆盖相同产品 ID 的选择器，不新增第二个大陆集合。生成按以下顺序处理：

1. 固定来源版本，解析分类与 include，保留精确域名、后缀、Core 可表达的关键词/正则和属性语义。China 与 ChinaMax 均同时读取主体和 `_Domain` 伴随文件；域名路径不混入 Geo IP。
2. DLC、ChinaMax、China、ACL4SSR、Sukka 等已选定的成熟分类直接贡献规则，官方明确端点也可单源采用。新增域名不必先存在于旧身份目录，不按来源数量投票。
3. 应用有明确原因的具体例外：发布者测试标记、dotless TLD 与国家名关键词快捷项、来源自含的市场冲突，以及过宽共享云父域。不能将整个成熟补充源永久放入 reference-only。
4. 合并成员，先检查跨市场冲突，再做等价压缩。精确主机不能变成父域后缀，不能把不支持的 AND/NOT 拆成 OR。

具名政教命名空间 `gov.cn` / `edu.cn` 保留；`cn` / `china` / `ru` / `russia` 等国家名关键词及 dotless TLD 不因成熟源成员身份自动接纳。

中国大陆只提供 `region/cn`。俄罗斯服务可同时属于 `region/ru`、`category/ru-services` 和有实际用途的其他类别。两个俄罗斯视图的重叠是用途重叠，不是重复来源的独立票数。

报告保留来源版本、血缘、选择器输入和接纳量、覆盖去重、拒绝原因、每来源/原因的有界样本及最终来源支持。来源支持可以重叠，不能直接相加成为净新增，也不表示统计独立。报告不建立逐行持久诊断平台。

## 俄罗斯聚合修正

冻结 DLC `476b009f4d0176426958b3fdadf87f2a2688baa5` 的 `category-ru` 包含具名银行、保险、运营商、邮政和产品，也包含 `tld-ru`。只跳过 `tld-ru` include 子树，保留其余具名分类；不能因为聚合里含 `.ru` 就丢弃整个聚合。

该子树的 `.ru`、`.su`、`.moscow` 等十一项是注册级快捷项；另排除精确谓词 `DOMAIN-SUFFIX,ru.com` 和 `DOMAIN-SUFFIX,ru.net`。[Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat) 将后两者列为注册边界。排除这些宽谓词不影响单独具名的下级服务。

原正式数据 `aa9a000d61cfdf7abd982e42` 中，`region/ru` 为 1,057 个域名谓词、`category/ru-services` 为 1,530 个；`beeline.ru`、`mts.ru`、`rt.ru`、`megafon.ru`、`tele2.ru`、`pochta.ru`、`mcc250.pub.3gppnetwork.org` 都未被覆盖。它们由分类选择器遗漏导致，不是缺少 Geo 凭据。

具体例外保持可查：

- 显式 CN、广告和遥测属性按选择器过滤。正向父域仍可能覆盖广告子域，不伪造 NOT 减集。
- `yandexcloud.net`、`vkcs.cloud` 整个共享父域暂不纳入，已明确列出的精确端点可保留，不扩张到其他租户。
- DLC 注释指出 My.Games 已退出俄罗斯市场、VK Cloud KZ 是哈萨克斯坦业务；配置中的六个根域暂缓当前市场归类，保留具体原因，而非断言其错误或恶意。
- `.yandex` 是 [IANA 登记的品牌顶级域](https://www.iana.org/domains/root/db/yandex.html)，区别于通用 `.ru` 快捷项；当前有界域名策略尚未接纳这一特殊范围，仍明确列为缺口。

## 正向冲突不能隐瞒

俄罗斯银行分类明确包含 `DOMAIN-SUFFIX,ru.ccb.com`，大陆分类包含 `DOMAIN-SUFFIX,ccb.com`。普通正向 `.list` 无法从 CN 父域中减去 RU 分支。

配置仅用精确谓词、真实来源和原因声明 `cn_market_overlaps`，保留两项并报告 `unresolved-positive-overlap`；不删除整个大陆银行主域，不悄悄删除俄罗斯分支，不假定用户的规则优先级或出口。该声明不授权其他 `ccb.com` 子域。

其他交集先于压缩处理。被 DLC 具名大陆服务范围完整覆盖的其他集合谓词排除；国内访问可用性造成的子域相交不等于大陆独有身份，不能因此整体删除国际服务父域。实际有界谓词交集逐项报告其保留或暂缓原因；普通正向规则不能安全减集时不伪造 NOT，也不假设顺序。一般 keyword / regex 与无限后缀语言无法证明互斥时，保留原规则并按组汇总未知模式交集和有界样例，不为每一项复制未知记录。发布验证复核这些声明及汇总，不能把“有报告”宣传为零重叠或全部解决。

## 固定旧语料的边界与回归

旧 `airrelay/rules` 固定 commit `20a3b237005292e60b62603e934b3972348366b4` 的 `region/ru.list` 可下载，原文件 1,196,565 字节、SHA-256 `65f4ffd8eb170bd10baaf46cbaedc1efbb5d42f497de5c687774bfb6d5b31daf`。其中只有 15,361 条 IPv4 与 16,494 条 IPv6 CIDR，域名为零，不能拿这份文件宣称完成俄罗斯旧域名迁移；旧 CN 域名按独立固定语料作语义比较。

`tests/test_regional_domains.py` 与 `tests/test_domain_strategy.py` 使用离线夹具覆盖具名 include、TLD 负样本、成熟补充源新增、共享云精确范围、压缩、跨市场声明、来源失效和分原因样本。完整生成的最终覆盖、差异和发布状态以当轮构建报告及实际 release 为准，选择器研究数量不冒充最终发布数量。
