# AirRoute Data

面向 **AirRoute** 的被动数据生产系统：GitHub Actions 编排，Python 3.11+ 批处理。源码在 `main`，同一仓库的 `release` 分支保存生成产物。它从零替换了旧的 Rust 控制中心、Web Console、数据库服务、节点和 Globalping 调度；没有旧接口或兼容层。

只下载已经存在的公开资料。**不会对规则目标进行 DNS、TLS、HTTP、ping 或 traceroute 测量**，不使用 MITM，不生成 UA，不决定客户端最终出口，也不输出其他客户端格式。

## 本地运行

Python 标准库即可运行生产链，不需要安装数据库、Rust 服务或 Node.js。

```sh
python3.12 -m unittest discover -s tests -v
python3.12 -m airroute_data snapshot --output .build/input
python3.12 -m airroute_data build \
  --snapshot .build/input/snapshot.json --output .build/candidate \
  --report .build/build-report.json
python3.12 -m airroute_data validate .build/candidate
```

每次使用新的空输入/输出目录，避免在计算中途刷新来源。构建阶段离线运行；重放同一输入与配置得到相同字节。`snapshot --source dbip --source iplocate ...` 可选择来源做针对性验证，未选来源会如实标记。离线获取测试支持 `--fixture-dir`；完整合成输入和端到端示例见 `tests/test_pipeline.py`，不能把夹具覆盖量当作真实全网覆盖。

五家国家库均有获取与解析入口，但不是五家都能匿名下载：

| 来源 | 免费获取条件 | 默认公开派生 |
| --- | --- | --- |
| MaxMind GeoLite Country | 免费账号、`MAXMIND_ACCOUNT_ID`、`MAXMIND_LICENSE_KEY` | 暂不使用：长期保留旧版本与其删除义务需要先解决 |
| DB-IP Country Lite | 匿名月度 CSV | 可用，保留署名 |
| IPinfo Lite | 免费账号、`IPINFO_TOKEN` | 有完整库凭据时使用，样本不充当整库 |
| IP2Location LITE DB1 | 免费账号、`IP2LOCATION_TOKEN` | 有凭据时使用，遵守下载与署名条款 |
| IPLocate Country | 官方公开 Git 数据发布链 | 可用，保留署名及 share-alike 条款 |

凭据仅通过环境变量或 Actions Secrets 提供，不放进配置、日志或产物。本地遗留的私有 `.cache/` 有意保留并忽略，不参与新系统或发布；本次重建不清理仓库外数据、生产环境或历史凭据。详细版本、频率、许可、字段语义和当前状态见 [来源说明](docs/SOURCES.md)。

## 输出与判断边界

一次候选包含：

- `region/*.list`：16 个版本化大区；中国大陆只有 **`region/cn.list`** 一个公开集合，先域名再 IP。
- `provider/*.list`、`service/*.list`、`category/*.list`：少量有独立价值的服务及类别；大陆服务与海外集合保守排除。
- `geo.ardb`、`asn.ardb`：ARDB v1 的未压缩随机读取文件。地区 `.list` 和 Geo 文件来自同一份清洗结果；ASN 多起源允许跨组重复。
- `regions.json`：稳定数值 ID 与大区映射。俄罗斯为独立分组，不重复进入欧洲和亚洲。
- `manifest.json`：同一数据版本、格式/注册表版本、逐文件长度和 SHA-256。
- `reports/`：可用与缺失来源、血缘、完整未知/分歧区间、CN/RU 覆盖、BGP 多起源、辅助清单对照、域名隔离及出处。
- `ATTRIBUTION.md`：输入版本与来源署名。原始供应商库和凭据不进入公开产物。

国家数据先统一区间边界，再映射项目大区。默认至少两个有信息的血缘组一致、没有跨大区反对信息时才归类；来源缺失不投票，同源镜像不加票。该策略是保守门槛，**不是统计独立性证明或准确率**。冲突、单源与全源缺失保持未知，在明确的地址空间契约内完整报告；不会把未知默认为海外。

BGP/ASN 表示当前采集视角的路由起源。RIR 注册国、RPKI、路由清单和 geofeed 都不单独证明物理位置。DLC 与官方端点表示服务身份，也不通过 DNS/IP 位置反推服务。完整 MRT 支持更具体前缀和逐 peer 视角；RIS 摘要缺少的粒度如实记录。

`.list` 只输出本项目已验证的 Core 规则子集，不包含动作或默认 `no-resolve`。不能等价表示的 AND、NOT、嵌套、歧义通配符及正则进入隔离报告，不进行有损扁平化。更多见 [规则语义](docs/RULES.md) 和 [Geo/ASN 语义](docs/GEO.md)。

## Actions 与发布

[工作流](.github/workflows/build.yml) 每天 03:17 UTC 或手动从 `main` 执行：测试 → 固定输入 → 生成候选 → 验证 → 发布。免费供应商的访问频率优先；不绕过限制，不为补五源使用镜像。构建只读权限，发布任务才授予 `contents: write`。

`release` 布局：

```text
current.json
versions/<data_version>/manifest.json
versions/<data_version>/geo.ardb
versions/<data_version>/asn.ardb
versions/<data_version>/region/cn.list
...
```

完整版本目录与 `current.json` 在同一个 Git 提交中切换。消费者先读取入口，再固定版本目录并核对摘要；不分别请求会移动的文件入口。失败、异常覆盖变化、过期源码、旧发布序号或远端分支竞争均不能覆盖已成功版本；相同产物不提交。普通非 force push，超时按已保存提交 SHA 对账。

本地发布命令会实际写远端，需自行确认账号与仓库；日常构建不隐式发布：

```sh
python3.12 -m airroute_data publish --candidate .build/candidate \
  --repo . --source-sha "$(git rev-parse HEAD)" --sequence 123 --attempt 1
# 回退是一个正常向前提交，序号必须更新：
python3.12 -m airroute_data rollback --repo . --version <已有版本> \
  --source-sha "$(git rev-parse HEAD)" --sequence 124
```

序号对应工作流 `run_number`，重试对应 `run_attempt`。手动运行也必须保持递增。历史目录保留用于回退；来源许可不允许历史保留时，不可直接加入公开生成链。恢复限制与隔离 Git 验证见 [发布说明](docs/PUBLISHING.md)。

## 二进制与客户端互操作

[ARDB v1 说明](docs/FORMAT.md) 和 `tests/golden/` 是共享契约。只有一个小型 Rust 验证工具，**不是运行组件或 Rust crate**：它链接实际 Core 读取器，读取 Python 写出的同一组黄金样例及损坏文件。

```sh
AIRROUTE_CORE_IP_DATA=/path/to/AirRoute/crates/ip-data/src/lib.rs \
  python3.12 -m unittest discover -s tests -p test_ardb.py -v
```

未指定 Core 源码时，该跨仓库测试明确跳过；普通 Python 格式测试继续运行。已验证的文件读写不代表客户端安装层已接入这份大区注册表、manifest 和原子切换；该边界仍须在客户端另行验证。本仓库不修改客户端或 Core。

实际验证范围与缺源见 [验证记录](docs/VALIDATION.md)。
