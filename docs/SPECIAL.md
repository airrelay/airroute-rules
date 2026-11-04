# 特殊用途与 RealIP

所有客户端规则都位于 `special/`，维护入口为 `config/special.json`，生成器为 `airroute_data/special.py`。这里的列表描述匹配范围，不内置 DIRECT / PROXY、不指定解析器，也不执行网络探测；输出不携带 `no-resolve`，上游标志转换有记录。ASN 数据库单独为 `special/asn.ardb`，遵循 [ARDBv001 格式](FORMAT.md)，不是域名规则列表。

## 文件和用途

| 文件 | 内容和边界 |
| --- | --- |
| `special/lan.list` | RFC1918 私网、IPv6 ULA、环回、链路本地和标准本地名称 `localhost`、`local`、`home.arpa` |
| `special/shared.list` | `100.64.0.0/10` 共享地址；不能一概当成用户 LAN |
| `special/multicast.list` | IPv4 / IPv6 组播 |
| `special/broadcast.list` | 受限 IPv4 广播 |
| `special/benchmark.list` | 基准测试地址，包括可能用作 FakeIP 池的 `198.18.0.0/15`；不进入 LAN |
| `special/documentation.list` | 文档示例地址，不作地域或可达性证据 |
| `special/nat64.list` | NAT64 转换前缀，不作普通 LAN |
| `special/local-name-compat.list` | `.lan`、`.localdomain` 社区命名习惯，区别于 IETF 标准本地名称 |
| `special/connectivity.list` | 系统连通性与门户检测 |
| `special/ntp.list` | 官方资料与 DLC 所分类的时间同步匹配规则 |
| `special/stun-turn.list` | 官方资料与 DLC 所分类的 STUN/TURN 匹配规则 |
| `special/software-update.list` | 已选择的软件更新规则 |
| `special/public-dns.list` | 公共 DNS 服务端点；不是解析器配置指令 |
| `special/realip.list` | 单一 RealIP 名单，合并原基础与扩展规则及选定成熟兼容来源 |
| `special/asn.ardb` | 上游 ASN 的双栈前缀索引，供客户端编译规则时按需展开 |

LAN 的地址定义来自 IANA 特殊用途注册表及对应 RFC。共享地址、组播、文档地址、NAT64、基准测试分配各有用途，不能因为都被某上游称为 private 就合入 LAN。IANA 分配与特殊用途资料使用本轮冻结版本；必需资格输入缺失、损坏或解析失败终止构建。Geo 与正式 ASN 分别应用自身资格含义，不把所有特殊范围都同样排除；LAN 等列表仍按各自用途核对。

## 单一 RealIP 名单

旧的 `dns/realip.list`、`dns/realip-optional.list` 已合并为 **`special/realip.list`**，不继续生成旧路径或兼容副本。原两份名单中的有效规则均进入同一集合，再按实际匹配语义无损去重。客户端或订阅配置必须改用新路径；旧 URL 不会自动跟随迁移。

RealIP 表示：命中域名时返回真实解析地址而不是 FakeIP。它不代表直连，不指定使用本地 DNS，也不决定最终代理出口。该名单包含标准本地名称、已维护的协议兼容记录和选定的 DustinWin `fakeip-filter` 上游域名规则。来源自己的分类可作为输入，不要求候选先被另一份用途目录或自定义厂商根域证明。

生成器保留可表达的 `DOMAIN`、`DOMAIN-SUFFIX` 和 `DOMAIN-KEYWORD` 语义：精确主机不会被改成父域后缀。重复或被已有规则完整覆盖的条目只输出一次，构建记录保存其来源和覆盖者。不能表达的正则、复合条件、IP、路由动作及反向查询处理会按原因记录，不伪装成普通 A/AAAA 例外。名单只反映上游兼容策略，不声称每个成员在所有客户端环境中都必须用真实地址，也不使用独立来源投票或置信分。

DLC 的 `category-ntp`、`category-stun` 用于相应普通 special 列表。原有后缀、关键字和正则在 AirRoute 支持的情况下保持原意，不再用“必须精确主机”把其全部过滤。NTP/STUN 服务用途与 RealIP 地址模式是不同事实：某个用途列表不会自动整体变成 RealIP 名单。

## 来源、记录和检查

生成器读取冻结版本的 DLC、blackmatrix7 Lan、ACL4SSR 局域网规则、MetaCubeX private、DustinWin fakeip-filter 及 IANA 注册表。重复发行、转换格式和共同上游不计作独立证据。社区 private 名单只做用途对照，不能把所有公开服务、反向区或共享基础设施都认定为 LAN。

构建记录保存来源版本与摘要、解析条目、选定规则、不能表达的项、合并后条目及实际覆盖关系。主机被父后缀覆盖表示无损压缩，不是丢失。详见 [构建记录](BUILD_RECORDS.md)。来源缺失、异常变动和空结果如实报告，不因历史条目数量、增长比例或维护的特定主机缺失而阻止发布。

必要工程检查仍保留：类型与格式、规范化、文件完整性、manifest 摘要及结果一致性。LAN 仍须在私网/本地语义内，不能误收 FakeIP、共享地址、全部组播或全部协议专用地址；RealIP 仍只含可表达的域名规则，不混入 CIDR、路由动作或解析器地址。标准范围检查不是历史数量门槛。

## 客户端接入

既有客户端接口说明参考 Aegir 的 `crates/profile-config/src/model.rs` 和 `crates/core/src/dns/model.rs`；本次没有修改或重新验证客户端/Core。`RealIpRule` / `DnsMatchExpr` 支持 exact、suffix、keyword、wildcard 和复合表达式；本文件采用其可直接等价表达的前三种正向规则：

| 列表类型 | `match.type` |
| --- | --- |
| `DOMAIN` | `domain` |
| `DOMAIN-SUFFIX` | `domain_suffix` |
| `DOMAIN-KEYWORD` | `domain_keyword` |

导入器应校验同版本 manifest 的摘要，保留原匹配类型，生成稳定 ID 并设置 `action: real_ip`。例如：

```json
{
  "id": "realip-dns-msftncsi",
  "match": {"type": "domain", "value": "dns.msftncsi.com"},
  "action": "real_ip",
  "reason": "NCSI DNS address validation"
}
```

当前读取到的 profile 使用内联 `dns.fake_ip.real_ip_policy.rules`，运行时使用 `dns.real_ip_policy.rules`。仓库生成文件不代表外部订阅导入、客户端设置更新或运行时生效已经完成。需要客户端提供明确的 RealIP 导入/订阅入口并迁移旧地址；不能把 `special/realip.list` 当成普通路由订阅安装后就宣称 DNS 模式已改变。

mDNS 组播传输、PTR 反向查询、分流 DNS 和用户路由器本地域名解析仍需客户端按协议处理，普通 A/AAAA 例外不能代替这些功能。客户端已有 builtin_categories 的行为也不会因生成名单自动改变。
