# 特殊用途与真实 DNS 地址名单

本页描述规则仓库生成的数据，不改变客户端设置。`special/*.list` 是描述性路由匹配数据，`dns/*.list` 是 DNS 返回地址模式的专用数据。二者均不含 DIRECT / PROXY、解析器选择或进程规则。

## 目录与实际范围

维护入口为 `config/special.json`，离线生成器为 `airroute_data/special.py`。每条维护记录有原因、证据链接和血缘；外部候选使用冻结快照，不在构建时访问目标域名或 IP。标准固定用途记录即使可选社区来源不可用仍能生成；失效来源在报告中明确标记，不伪称已更新。已下载 IANA 注册表若缺少所需固定分配，构建直接失败。

| 文件 | 用途 | 不代表什么 |
| --- | --- | --- |
| `special/lan.list` | RFC1918、IPv6 ULA、环回、链路本地，以及 `localhost`、`local`、`home.arpa` | 不包含全部特殊用途地址；不内置直连 |
| `special/shared.list` | `100.64.0.0/10` 运营商共享/部分覆盖网络使用的空间 | 不是 RFC1918；不是所有用户自己的 LAN |
| `special/multicast.list` | IPv4 / IPv6 组播 | 不混入单播 LAN |
| `special/broadcast.list` | 受限 IPv4 广播 | 不包括整个 `240.0.0.0/4` |
| `special/benchmark.list` | IPv4 / IPv6 基准测试分配 | `198.18.0.0/15` 可能是 Fake IP 池，绝不自动作为 LAN 旁路 |
| `special/documentation.list` | IETF 文档示例地址 | 不是可达性或地域证据 |
| `special/nat64.list` | 标准 NAT64 转换前缀分配 | 不是普通 LAN |
| `special/local-name-compat.list` | 可选 `.lan`、`.localdomain` 社区命名习惯 | 不是 IETF 标准本地名称，也不自动实现分流 DNS |
| `special/connectivity.list` | 官方明确的 Windows NCSI、Apple 门户检测端点 | 不豁免整个 Microsoft/Apple 平台 |
| `special/ntp.list` | 官方与 DLC 中明确的时间同步主机 | 不能据此断言每个 NTP 客户端必须返回真实 IP |
| `special/stun-turn.list` | 明确的 STUN/TURN 主机 | 不使用 `stun`、`turn` 关键字推断整个域名空间 |
| `special/software-update.list` | 已核实的 Apple 更新端点 | 不因更新服务就加入默认 Real IP |
| `special/public-dns.list` | 明确的 Google / Cloudflare 公共 DNS 主机和地址 | 不是配置解析器的指令，不自动成为 DNS 例外 |
| `dns/realip.list` | 保守的真实 DNS 地址例外 | 不等于直连，也不指定本地 DNS |
| `dns/realip-optional.list` | 可选的、逐主机的兼容扩展 | 不是默认必需项；不是整个游戏平台、VPN 或 UDP 的豁免 |

LAN 地址范围以 [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)、[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) 与对应 RFC 为依据。`.local` 来自 [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)，`.home.arpa` 来自 [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375)，`localhost` 来自 [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761)。`.test`、`.example`、`.invalid` 虽有特殊用途，但不是实际 LAN 服务，因此未一概纳入 LAN。当前也没有将所有单标签名称扩张成全域通配。

## Real IP 的准入

默认名单仅有五条：

```text
DOMAIN,dns.msftncsi.com
DOMAIN,ipv4only.arpa
DOMAIN-SUFFIX,home.arpa
DOMAIN-SUFFIX,local
DOMAIN-SUFFIX,localhost
```

NCSI 的 DNS 测试会检查地址内容，依据 [Microsoft NCSI 文档](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-ncsi-guidance)。`ipv4only.arpa` 的地址携带 NAT64 前缀发现意义，依据 [RFC 7050](https://www.rfc-editor.org/rfc/rfc7050)。无关的合成 Fake IP 会改变这类查询的事实。三个本地名称仍需要用户的解析路径和客户端协议处理支持；本名单不能替用户提供本地答案。

可选扩展采用明确主机：官方指定的连通性/时间同步端点，以及 DustinWin 候选中同时能由 DLC `category-ntp` / `category-stun` 确认用途的精确主机。DustinWin 本身派生自 DLC 与 ShellCrash，不作为第二张独立支持票。进入可选扩展表示可审计的兼容策略候选，不表示已通过主动实验验证该主机一定不支持 Fake IP。

保留窄范围的 `xnotify.xboxlive.com` 社区兼容项；没有充分依据将整个 Battle.net、Steam、Nintendo、Xbox、Google 或 Apple 根域豁免。其他游戏 NAT 和 VPN/覆盖网络的默认全集仍是缺口，而不是用宽泛规则掩盖。Tailnet 私有 DNS 名和 VPN 服务器地址依用户配置变化，不能把全部 `ts.net` 或 `tailscale.com` 当成用户本地网络。

[Surge 官方说明](https://manual.nssurge.com/book/understanding-surge/en/understanding-surge-en.pdf)用于核对 `always-real-ip` 的地址返回语义，不将其客户端行为直接当作 AirRoute 已完成的集成。当前名单不复制其中的任意通配，也不把支持 UDP 等同于必须真实地址。

## 核实的上游与排除实例

构建消费 DLC `private`、blackmatrix7 `Lan`、MetaCubeX `private.yaml`、ACL4SSR `LocalAreaNetwork` 与 DustinWin `fakeip-filter.list` 的冻结版本，并记录候选数、文件摘要、来源版本、用途和拒绝原因。它们是用途混杂的社区清单，不是可以整体并入 LAN 的标准注册表。

2026-11-03 冻结输入的实际离线结果如下；不是把文本差异解释为有效新增：

| 产物 | 实际规则数 |
| --- | ---: |
| LAN / shared / multicast / broadcast | 11 / 1 / 2 / 1 |
| benchmark / documentation / NAT64 | 2 / 5 / 2 |
| 社区本地名称 / 系统连通性 | 2 / 6 |
| NTP / STUN-TURN / 软件更新 / 公共 DNS | 77 / 358 / 6 / 10 |
| 默认 Real IP / 可选 Real IP | 5 / 441 |

DLC `category-ntp` 的 116 条候选中接纳 75 条精确主机；其余 41 条后缀不被擅自等同为单一端点。加上官方维护端点并无损去重后是 77 条。`category-stun` 的 359 条候选接纳 358 条精确主机，拒绝 1 个宽泛后缀。DustinWin 557 条候选中，433 条精确主机与已分类 NTP/STUN 端点相符，可进入可选兼容扩展；90 个宽泛匹配与 34 个缺少具体兼容依据的候选未因此获准。加入维护端点、去掉默认名单已覆盖项后，可选扩展为 441 条。这些计数有重叠，不能加总为独立服务数或独立来源票数。

IANA 实际 CSV 已用于复核 IPv4 的 11 个、IPv6 的 8 个所选注册前缀。组播分配另由 RFC 1112 / RFC 4291 定义，公共 DNS 地址另由服务商官方资料定义，不误称它们都在特殊用途注册表中。

三个具体拒绝实例：

- blackmatrix7 Lan 中的 `198.18.0.0/15` 只进入 benchmark 集合，不能进入 LAN。
- DLC、MetaCubeX 和 blackmatrix7 中的 `ts.net` 后缀未成为 LAN 或默认 DNS 例外，避免把所有租户和公开控制服务当成用户本地名称。
- DustinWin 中的 `battle.net` 后缀未成为 Real IP 例外；即使某个游戏端点有兼容问题，也不能推导出整个平台根域需要豁免。

报告为候选目录内的 `reports/special.json`，不把内部候选和拒绝清单发布成用户路由集合。

## AirRoute 客户端接入边界

本次只读检查了当前 Aegir 工作区中的 `crates/profile-config/src/model.rs`、`compile.rs`、`smart_real_ip.rs` 及 `crates/core/src/dns/model.rs`，没有修改客户端或 Core。

当前 `RealIpRule` 使用内联 `match`、`action`、可选 `reason` 等字段；表达能力包含 exact、suffix、keyword、wildcard、Any/All/Not。运行时 `real_ip_policy` 同样消费内联规则，目前没有可直接填写外部 `.list` URL 的 Real IP 专用订阅字段。本仓库因此只使用双方均能准确表达的 `DOMAIN` / `DOMAIN-SUFFIX`；不输出正则、IP、路由动作或解析器地址。

最小对接工作是：

1. 客户端新增明确的 **DNS Real IP 名单导入/订阅** 入口，按同版 manifest 获取并校验摘要，失败保留前一有效名单；不能把此文件当普通路由订阅安装。
2. `DOMAIN` 映射为 `{"type":"domain","value":"..."}`；`DOMAIN-SUFFIX` 映射为 `{"type":"domain_suffix","value":"..."}`。保持匹配语义，生成稳定规则 ID，并设置 `action: real_ip`。不要把精确主机升级成后缀，也不要复用 wildcard 的边界差异。
3. 用户明确选择是否启用可选兼容扩展。解析器选择仍由 DNS 规则决定，流量出口仍由路由规则决定。导入名单不能顺便修改二者。
4. 当前内置 `Ntp` / `StunTurn` / `GameNat` 等类别还存在基于关键字的宽泛匹配；新文件不会自动替换这些启用项。若客户端要提供“只按精确订阅控制”的模式，需要明确处理既有 builtin_categories 和 route_aware 优先关系，不能宣称生成精确数据后旧启发式已消失。

例如，内联 profile 规则可表示为：

```json
{
  "id": "realip-dns-msftncsi",
  "match": {"type": "domain", "value": "dns.msftncsi.com"},
  "action": "real_ip",
  "reason": "NCSI DNS address validation"
}
```

它位于公开 profile 的 `dns.fake_ip.real_ip_policy.rules`；编译后传入运行时 `dns.real_ip_policy.rules`。此例说明类型映射，并不声称本仓库已自动修改用户 profile。

mDNS 的组播传输、PTR 反向查询、分流 DNS 与用户路由器的本地域名解析，仍是客户端真实 DNS 行为。本数据既不对目标做拨测，也不声称普通 A/AAAA 例外可以解决这些协议层问题。

## 验证

`python3 -m unittest discover -s tests -p test_special.py -v` 覆盖离线确定性、非空输出、IANA 缺失/损坏、LAN 范围、Fake IP 误收、共享与组播边界、Real IP 类型和宽泛匹配、私有清单公共域名污染、血缘、可选端点准入与缺源报告。发布前独立调用 `validate_special_groups` 检查实际列表内容，不以报告自称合法代替校验。修改配置不能绕过 LAN 和默认 Real IP 的安全范围；集合存在时还必须完整覆盖其固定基线（LAN 的八段地址和三个标准名称、默认 Real IP 的五条规则）。即使删掉部分内容后重新计算摘要，发布校验仍会拒绝；等价的 CIDR 分拆按地址并集校验，不误判为缩水。
