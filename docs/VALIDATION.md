# 验证方法与边界

本文件说明当前源码的验证入口及应记录的指标，不保存具体部署地址、账户、节点标识、运行凭据、数据库副本、运维日志或历史发布流水。测试通过范围以对应环境的实际执行结果为准；本地、隔离 Linux、真实部署和外部服务验收分别记录，不能互相代替。

## 从干净源码开始

前端资源在 Rust 编译时嵌入二进制。`web/console/dist/` 不入库，必须先生成，不能仅在没有前端产物的目录执行 Cargo 命令。

```sh
npm --prefix web/console ci --no-audit --no-fund
npm --prefix web/console run build
npm --prefix web/console run test:audit
cargo fmt --all --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

发布构建入口为 `bash scripts/build-release.sh`，它先打包控制台再编译两个 Rust 程序。仅重建前端、仅编译或仅通过单元测试，都不能代替实际二进制运行验证。交叉编译可通过目标 triple 和链接器环境变量配置，不把本机工具链绝对路径写入仓库。

## 针对性回归入口

| 边界 | 当前测试入口 |
|---|---|
| 来源融合、完整覆盖、等价压缩 | `tests/fusion_value.rs`、`tests/optimization.rs`、`tests/sqlite_build.rs`，以及 `src/rules.rs` / `src/geo.rs` 内联测试 |
| BGP 范围与稳定候选 | `tests/bgp_sampling.rs`、`tests/sampling_lifecycle.rs`，以及 `src/sampling.rs` 内联测试 |
| 零变化差分、版本激活、批量同步 | `tests/build_delta.rs`、`tests/store_batches.rs`、`tests/server_refactor.rs` |
| 共享任务、能力、并发与重连 | `tests/logical_jobs.rs`、`tests/dispatch_safety.rs`、`tests/quic_transport.rs`、`tests/scheduler_v2.rs` |
| 尝试身份、重复/迟到结果、证据资格 | `tests/receipt_v3.rs`、`tests/lifecycle.rs`、`tests/dns_cache.rs` |
| DNS 发现周期和短 TTL | `tests/discovery_renewal.rs`、`tests/passive_discovery.rs` |
| Globalping 余额、发送边界及旧状态 | `tests/globalping_pool.rs`、`tests/quota_migration.rs`，以及 `src/globalping/` 内联测试 |
| Git 普通推送、拒绝及未知提交恢复 | `tests/github_publish.rs`、`tests/publish_recovery.rs`、`tests/oauth_refresh.rs` |
| 核查列表、筛选和关联查询 | `tests/audit_http.rs`、`tests/audit_issues.rs`、`tests/audit_queries.rs`、`web/console/audit-routing.test.mjs` |
| JWT、重启保留、退出和凭据轮换 | `tests/console_sessions.rs`，以及 `src/console_session.rs` 内联测试 |

按改动选择相关目标，保留原始失败及修复后的同条件结果，不为一个文案或示例替换重复运行完整构建与网络测量。测试使用临时目录、合成凭据及本地模拟服务；不要把真实凭据或运行数据复制进夹具。

## 完整构建与补证验收

使用固定来源、配置和观测快照，分别验证零变化、小变化与全变化：

- 同输入产生相同公开规则及 IP 库，域名发现来自压缩前接受的规则行。
- 有效分歧继续按确定性策略输出；无来源信息时报告覆盖缺口，不伪造归属。
- 公共 release 与私有 build 绑定正确，内部清单不进入公开发布目录。
- 零变化不写待测语义项，小变化不触碰无关项；激活事务不逐条更新全部在线事项。
- 最新清单短批差分可恢复，旧批次不能覆盖新构建；原租约、结果、费用及 GP 意图保留。
- 同一目标、方法和必要视角不按节点复制任务；有合适积压和容量时持续补位。
- IPv4 有界候选与 IPv6 已知候选保持区别，候选地址不能冒充真实响应或前缀位置证据。
- 三次机会、执行器故障、目标负响应、重复/迟到回执、重连、丢 ACK 和旧在途迁移均有明确结果。
- GP 已知 ID 继续回收；未知提交保留防重和账目，不用新任务或新轮绕过。

规则问题、去重任务和原尝试记录分别计数。已有回传不等于地区或服务归属已核实，辅助目标发现的完成量不能算作业务问题解决量。

## 隔离运行与性能测量

`--offline` 只控制构建来源缓存，`--interval-hours 0` 只关闭定时构建；两者都不是全系统断网开关。演练使用独立 root/data、禁用真实账户和发布配置，并在网络隔离环境运行。不要对运行中的数据目录执行压测、直接复制 WAL 主文件，或主动消耗外部测量额度。

现有复现工具为 `scripts/measure-refactor.py`、`scripts/measure-linux-service.py` 和 `scripts/fixtures/isolated-node.rs`。参数通过命令行指定，报告留在源码仓库外。opt-in 压力测试见 `tests/refactor_performance.rs`、`tests/audit_performance.rs`。

同机、同输入、同负载比较以下指标：

| 维度 | 应记录内容 |
|---|---|
| 构建 | 下载/解析/生成/验证/激活/后台同步阶段耗时、完整链路时间 |
| 内存 | 控制器及相关子进程的整服务 cgroup 峰值、预算、swap 和 OOM 事件；夹具准备单独计量 |
| CPU | CPU 时间/唯一实际任务、CPU 时间/合格有效结果；区分未执行、缓存复用和真实网络执行 |
| I/O 与数据库 | 实际文件读写、WAL 峰值、扫描量、行变更数、写锁持有/等待时间 |
| 交互 | 正常列表及统计 p95、领取/回执延迟、心跳是否按期处理 |
| 恢复 | 关键中断窗口、未决意图、重复接纳、账目及版本指针的一致性 |

行变更数不是 SQL 执行次数，进程重启后的低峰值不是完整构建峰值，单条查询微测也不是端到端性能。需在目标 Linux 环境按实际整服务预算验证，并明确输入是真实冻结来源还是合成压力数据；没有覆盖的环境与负载应直说尚未验证。

## 二进制与界面

构建后检查内嵌 HTML/JS/CSS，验证健康检查、认证、缓存头、SPA 路由和错误路径；将二进制复制到独立目录运行，确认它不依赖源码中的前端 dist。已有辅助脚本为 `scripts/verify-embedded.mjs`。

控制台 JWT 应验证同一数据目录跨进程重启保留登录、退出后的旧 Cookie 在重启后仍无效、管理员凭据轮换使旧 Cookie 失效，以及篡改/过期/错误声明被拒绝。HTTPS 的 Cookie 属性、跨域拒绝和 Bearer/节点认证隔离分别检查；任何报告都不能保存会话值。

Git 发布用临时本地仓库和模拟响应验证普通非 force 推送、ref 竞争、拒绝、超时及按 SHA 对账。真实发布、实际节点和真实第三方额度需要在对应部署中单独验收；仓库里的示例和本地测试不能证明这些外部行为。
