# AirRoute Data

面向 **AirRoute** 的被动数据生产系统：Python 3.11+ 批处理，GitHub Actions 编排。源码在 `airrelay/airroute-rules` 的 `main`，最终产物继续发布到 `airrelay/rules` 的 `main`；这是用户确认的当前目标，不改回旧同仓 `release`。下载地址及旧地址迁移见 [发布说明](docs/PUBLISHING.md)。没有常驻 Rust 服务、Web Console、探测节点、Globalping 或旧接口兼容层。

只下载已经存在的公开资料，不对规则目标发起 DNS、TLS、HTTP、ping 或 traceroute 测量。不使用 MITM、不生成 UA，不为其他客户端生成格式，不决定用户的最终出口。

## 本地运行

生产链使用 Python 标准库。每轮使用新的空输入、输出及记录目录，固定输入后离线计算：

```sh
python3.12 -m airroute_data snapshot \
  --output .build/input --record-dir .build/record
python3.12 -m airroute_data build \
  --snapshot .build/input/snapshot.json --output .build/candidate \
  --report .build/build-report.json --record-dir .build/record
python3.12 -m airroute_data validate .build/candidate
python3.12 -m unittest discover -s tests -v
```

同一输入、配置及生成器产生确定性输出。`snapshot --source <id>` 可选择材料；未选来源如实标记，不以样本冒充完整库。构建必需的主地域源下载、解析或完整性校验失败时明确失败，不能用备选整库悄悄替代。可选来源缺少凭据不会被伪称成功，也不阻塞与其无关的工作。

只更新域名和特殊规则时，可复用一个固定提交、完整且通过工程校验的当前格式产物目录：

```sh
python3.12 -m airroute_data build-domains \
  --snapshot .build/domain-input/snapshot.json \
  --baseline .build/release-base --output .build/domain-candidate \
  --record-dir .build/domain-record
```

该路径复用地域 **IP 列表**和 `special/asn.ardb`，在记录中保留实际来源版本、基线及获取时间，不重新解析国家库，也不把旧 IP 宣传成新数据。不读取或保留隐藏 Geo 数据库；旧格式基线应先完整重建。

## 四类客户端产物

| 分类 | 主要内容 |
| --- | --- |
| `region` | 16 个既有大区的 IP 列表；中国大陆分为 `region/cn-ip.list` 和 `region/cn-domain.list`，后者仅为域名等受支持非 IP 类型。其他地域（含俄罗斯）仅含 IPv4/IPv6 |
| `category` | AI、开发、游戏、媒体、金融、俄罗斯服务等用途集合；允许合理重叠，也保留上游中国服务成员 |
| `provider` | 服务商自身产品及有独立分流价值的单项服务；原独立 `service` 产品移到这里，不把单项服务扩写成整家公司 |
| `special` | LAN、特殊地址/端点、统一的 `special/realip.list`，以及唯一的二进制 `special/asn.ardb` |

不再输出 `geo.ardb`、旧 `region/cn.list`、`service/` 或 `dns/` 产物。CN 两份列表是语义明确的拆分，无长期兼容别名。客户端和下载配置需要同步改路径；本仓库没有修改客户端，也不宣称新订阅已自动生效。

`manifest.json` 将列表、ASN、来源版本及逐文件长度和 SHA-256 绑定到同一个数据版本。`regions.json` 是大区映射元数据，`ATTRIBUTION.md` 保存来源许可署名；它们不是新增的客户端规则分类。构建报告和详细索引只保留在本地或 Actions artifact，不混入正式订阅。manifest 使用 `region_registry_version` 记录地域映射版本。

## 生成原则

地域来源顺序集中在 `config/geo-policy.json`：**IPLocate → MaxMind → DB-IP → IPinfo → IP2Location**。按真实区间边界切分，同一来源内部处理更具体范围；主源有有效地域就采用，其他源冲突只记录，不把整段改为未知。主源在某段缺信息时按顺序补缺；全部缺信息才报告未知。这是确定的产品策略，不是来源绝对准确或统计独立的证明。

域名以 DLC、blackmatrix7、ACL4SSR、Sukka 及官方机器可读端点为生成输入。正确展开 include、属性和引用，保留精确/后缀/关键词/正则原意，只做格式检查、必要规范化及可证明等价的去重。不要求候选先命中厂商根域、身份目录或多源投票。CN 与全球用途集合可以重叠；不能用差集悄悄删掉中国成员。详见 [规则语义](docs/RULES.md) 和 [CN/俄罗斯归类](docs/REGIONAL-DOMAINS.md)。

BGP、RIR、注册国和 geofeed 是各自语义的辅助信息，不单独作为物理地域真值。ASN 保留可用双栈、多起源及采集视角，宽前缀与特殊 ASN 明确报告；观测成员不等于网络实际所有权。详见 [地域与 ASN](docs/GEO.md)。

`.list` 不包含 DIRECT/PROXY 动作，输出不携带 `no-resolve`；上游显式标志也按产品约定去除。不能由 Core 等价表达的规则记录来源、类型和原因，不扁平化 AND/NOT。`special/realip.list` 只描述 DNS 返回地址模式：不返回 FakeIP，不等于直连，也不选择解析器；对接边界见 [特殊规则](docs/SPECIAL.md)。

## 来源、记录与发布

五家地域来源均有解析入口。MaxMind 需要 `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`，IPinfo 需要 `IPINFO_TOKEN`，IP2Location 需要 `IP2LOCATION_TOKEN`；DB-IP 与 IPLocate 有无需令牌的公开下载链。凭据只放环境变量或 Actions Secrets。来源事实、许可和血缘见 [SOURCES](docs/SOURCES.md)，当轮可用状态以实际快照与记录为准。

Actions 每天 03:17 UTC 或手动运行：基本检查 → 固定输入 → 完整构建 → 工程校验 → 按工作流参数发布。历史数量、地址量、增减幅度与未收录项用于解释变化，不作为自创的内容正确性门槛；损坏、必需输入缺失、格式不兼容、摘要或 manifest 不一致仍失败。发布保持原子 Git 提交、并发防护和普通非 force push，失败保留上一版。

正式树不使用 `versions/` 或哈希路径。整包消费需固定产物仓库 `main` 的提交 SHA，再读取 manifest 和各文件，避免移动分支跨请求混版。具体流程及回退见 [PUBLISHING](docs/PUBLISHING.md)。

[构建记录](docs/BUILD_RECORDS.md) 支持按域名、IP/前缀、ASN 和产品反查；成功、失败和跳过发布分别标识。[覆盖说明](docs/COVERAGE.md) 解释计数口径，[验证说明](docs/VALIDATION.md) 列出当前检查边界。ASN 的 [ARDBv001 契约](docs/FORMAT.md) 不变；跨仓库读取和客户端接入必须用实际证据另行确认。
