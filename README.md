# AirRoute Rules

Rust 规则构建控制中心与分布式探测节点，生成域名优先的通用分流规则和 IP 库。保留 AirRoute 支持的域名、IP、ASN、进程、端口等原子条件，不携带 DIRECT、节点组或客户端出口策略。

全部 **376** 个规则集合：地区 **16**、分类服务 **24**、服务商与产品 **315**、特殊用途 **21**。来源、选择器、成员和范围由 [config/recipes.json](config/recipes.json) 等配置维护。公开产物是四类 `.list`、README 和正式 `ip-library.csv`；原始证据和待补证清单只留维护侧。

## 本地运行

需要 Rust 1.89+、Node.js 22.12+、npm、Git 和本机 C 工具链。Node 只用于打包，运行时为内嵌 Web Console 的 `rules-control` 与出站 QUIC 探测程序 `rules-probe`。

```sh
bash scripts/build-release.sh
./target/release/rules-control build
./target/release/rules-control build --offline
./target/release/rules-control validate dist
./target/release/rules-control serve --bind 127.0.0.1:8787
```

打开 <http://127.0.0.1:8787>，使用数据目录管理员令牌或预设 `AIRROUTE_ADMIN_TOKEN` 登录。默认仅监听本机，每 24 小时构建一次。`--root` 指向包含 config 的目录，`--data` 指向数据目录。

控制台登录采用 8 小时有效的 HS256 JWT，放在 HttpOnly、SameSite=Strict Cookie 中，HTTPS 下同时设置 Secure。正常更新和重启保留登录态；退出登录会持久撤销当前会话，更换管理员令牌会使已有会话失效。数据目录中的 `console-session-key` 和 `console-session-revocations.json` 由服务以 0600 权限管理，备份和更新时须保留，勿公开。首次从旧的内存会话升级仍需重新登录一次。

`serve --interval-hours 0` 只关闭周期构建，`--offline` 只复用构建来源缓存；均不关闭观测、发现或 Git 网络。演练须另用独立副本、fixture 凭据和出站隔离。生产迁移、部署、真实发布和额度消耗单独批准后执行。

控制台沿用 React/TS/Vite/Mantine/TanStack，不新增框架或独立运行服务；页面为概览、规则目录、规则核查、探测资源、构建版本和 GitHub 发布。“规则核查”内按规则问题、探测任务、执行记录追溯，旧任务和争议地址继续可用。

## 每日构建与补证闭环

```text
固定来源、已有观测和判断规则
           ↓
完整规则集 + IP 库 + 私有待补证清单
           ↓
必要版本指针激活 → 最新清单独立有界差分
           ↓
共享任务 → 自有节点 / Globalping → 保存结果
           ↓
下一次每日构建使用新结果
```

构建不等新观测，不逐条触发重建，不提供人工裁决入口。历史决定及回执保留只读；新构建按固定来源、合格观测和确定性策略生成完整数据。

每个对象都尝试匹配适用的已有观测，即使第三方一致。IP 优先采用能直接回答事实、范围适用、近期合格且互不矛盾的观测；否则同类来源先映射大区，由独立有效源严格多数选择，无多数时 IPLocate 为主、DB-IP 为备。镜像不重复计票，缺失不反对。过期、失败、无结论或矛盾观测不强盖来源；ping/traceroute/BGP/登记国不是物理位置，单 IP 不扩前缀。当前实际采集只提供 DNS、可达性及目标负响应，没有可信目标位置或服务所有权事实生产入口，快照中这两类事实计数如实为零，归属不能冒充由 traceroute 自动核实。

有效分歧按明确策略输出，并保留仍缺证据的问题，不直接剔除有效范围。全部来源与合格观测都无信息时明确覆盖缺口，按覆盖契约处理，不伪造或静默漏数据。域名按对应服务分类、明确官方端点及有效来源，不用 DNS/IP 地区反推服务归属。

解析、计算、文件生成与验证在写事务外完成；激活只切必要版本和可靠终态，不把全部 cases/jobs/派生数据写进激活事务。内部清单按 `build_id` 关联，新目录只保留 `manifest.sqlite3` 与 `build.json`；完整原始争议在 manifest.cases，manifest.domains 从压缩前完整接受规则中提取可发现 exact/suffix 主机名，不重复输出 JSONL，也不从最终 `.list` 反推。公开目录按 `release_hash` 不可变。

最新清单后台分页差分，只新增、实质变化或确需复测时写；不变项不改 `updated`、不重建任务。短批次复核新证据和旧在途，持久游标/build fence 支持半同步崩溃恢复，不让旧 build 覆盖新需求。旧全量规划、facts 重写及域名同步停用；有用读取投影和历史状态保留。

## 规则和 IP 库

中国大陆只公开 `region/cn.list`：国内域名优先、统一处理 IP 兜底；`cn-geo` 仅为内部大区 ID。其他地区不把供应商总部或 DNS/CDN 地址当作服务身份。

正式 IP 库 `ip-library.csv` 的列是 `family,start,end,region,anycast`，family 为 4/6，起止均含端点，region 与 `region/*` 规则集使用同一公开标识（如 `cn`、`us`），anycast 为 true/false。内部 `cn-geo` 不导出。它和规则一起参与 release 哈希、完整校验及 Git 发布。控制台规则目录提供 `/api/ip-library` 下载入口，发布仓库对应根目录 CSV。

集合内只做有证明的等价压缩：已有后缀/关键词或能严格证明覆盖的正则消除冗余；不从子域发明父域。CIDR 按方向、地址族和修饰符精确合并，保留地址洞。`*.example.com` 按 AirRoute 语义同时覆盖根域和子域，不能保证其他内核同义。

配方边界、共享基础设施、PSL、IANA 地址策略和质量场景继续约束输出。非法/损坏数据和不能忠实转换的谓词使验证失败，不能把完整性失败解释成“无反对意见”。来源、许可及证据边界见 [docs/SOURCES.md](docs/SOURCES.md)，当前链路合同见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 节点和共享任务

控制台注册自动生成节点 ID 和一次性密钥，下载信任证书并按 [config/probe.example.toml](config/probe.example.toml) 配置。协议见 [docs/TRANSPORT.md](docs/TRANSPORT.md)。探测机需安装 traceroute 并授予权限，缺失时返回真实错误。

```sh
# 节点环境中设置 AIRROUTE_NODE_TOKEN，配置 ID、控制中心与信任证书。
./target/release/rules-probe --config my-probe.toml
# observe 只登记临时需求；tick/discover 会执行相应外部请求。
./target/release/rules-control observe --target chatgpt.com --regions us,europe,cn-geo
./target/release/rules-control status
```

一个逻辑需求表达实际目标、方法及必要视角，不按节点/账户/build 复制。一个协调者原子检查能力和容量、异步执行回收并及时补位。自有节点默认并发 10，独立可调 1–1000，无自有全局上限；断连、重连、乱序心跳和迟回执绑定原 attempt/token，旧空位不能重复派发。断线只立即归还可证明未发送的预占，已开始的尝试保留原 token/租约到有效补传或截止时间，防止重连造成真实执行重叠。

GP 优先自有节点覆盖不了的必要视角，没有可执行的此类工作时领取双方共享任务；自有节点在线不再排他阻止 GP。没有默认第二视角、第二时间窗或全地区完成门槛。没有精确目标继续等待，不生成假 traceroute、不扫网段。目标发现使用接受域名的 A/AAAA、真实端点响应及 Atlas 既有结果，不创建 Atlas 测量。

每需求每轮最多三次实际执行是硬业务规则，自有/GP 合并计数，证据足够就停止。执行器故障换合适执行方，目标超时/拒绝仍保存本次观测，必要确认优先换运营商。确定未执行不计次数，但坏节点不能反复领拒。耗尽冷却 24 小时是建议并实现的默认策略，仅在新的每日构建仍需该证据时开新轮，不能按墙钟无限重测。正常到期新轮不累加过去失败，但单调尝试身份、历史和费用保留。

原观察时间与资格用于复用，重传不续期，DNS 沿用 TTL。trace 正响应 86400 秒、目标负响应 300 秒是可由明确 profile 策略覆盖的建议新鲜度默认；旧无绝对期限合格证据使用七天兼容回退，不把这些值当成周期重测规则。HTTP 成功、finished 或请求地区不是合格证据，实际方法/目标/地区/必要 ASN 均需验证。旧尝试只入可信历史，不完成新尝试；GP unknown 未解决前不能通过新轮/任务绕过。详见 [docs/SCHEDULING.md](docs/SCHEDULING.md)。

## Globalping

控制台支持账户新增、编辑、停用和删除，初始配置见 [config/globalping.toml](config/globalping.toml)。每账户独立查询官方免费余额/reset，并扣除未确认预留；没有本地小时/每日限额，不增加前端手填预算。UTC 小时账仅审计，不能重置 provider 余额。

按探针测试数计成本，实际提交启动至少间隔 5 秒，保留按官方余额延长节奏。同账户启动串行、响应异步，全局最多 16 活动 GP 领取槽；轮询每轮 LIMIT 16 是另一个限制，空 ID unknown 不占正常回收批次，不制造测量填满额度。

先保存意图、attempt、账户和预留，区分可证明未发送的 prepared 与进入发送边界的 sending。后者崩溃、超时或 202 未落 remote ID 均为 unknown，不自动退款/重发；已知 ID 独立回收。删除凭据仍保留恢复记录，释放槽或换小时不抹账。provider GET/POST 非原子，不能承诺外部恰好执行一次或外部竞争下绝对零积分；报告 credits 消耗时暂停当前窗口新增。

## 导出、发布和数据切换

控制中心保留 bundled SQLite WAL、共享 jobs、必要投影与远端恢复状态，无需 PostgreSQL/Redis/新服务。规范目录在 `data/releases/`，内部清单在 `data/internal-builds/`，缓存及受限凭据不随二进制替换。`dist` 通过持久 export pending、当前版本复核和 guard 恢复，防止旧导出覆盖新版本。

GitHub 目标默认 `example/rules` / `main`、发布默认关闭。支持仓库 Token 和 OAuth Device Flow，短期授权可自动续期。Git 队列绑定 build/release、仓库、分支、基线与 prepared commit SHA；重试不把旧产物 rebase 成新提交，普通非 force push 后核远端 SHA。超时先按 SHA/祖先核账，不能确认保留 unknown；旧无持久 SHA 的不确定发送不盲推。本地当前版本与远端已核实版本分别记录。只发布规则、CSV 和 README，不上传内部证据。

先用 SQLite backup API/`.backup` 取得一致副本，在独立 root/data、fixture 和隔离出站环境演练，不能仅复制活跃 WAL 主文件。旧 job ID/token、结果、历史决定、目标、费用、租约、已知/未知远端状态保留；新领取也受旧在途约束。生产切换前停旧控制器/生成器，只启一个新路径。

当前没有 `migrate --dry-run` 或全局“只暂停新领取”CLI。回退先停止控制器核兼容性，不能拿旧备份覆盖切换后的结果、费用和远端状态。操作边界见 [docs/SCHEDULING.md](docs/SCHEDULING.md)。

## 验证

```sh
npm --prefix web/console ci
npm --prefix web/console run build
cargo fmt --all --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

针对固定输入重复性、范围正确、零变待测不写、全变 O(1) 激活、短批同步/领取/回执并发、重连、每轮三次、迟回执、半同步崩溃、unknown 费用恢复进行验证。同机同快照比较完整构建、写量、写锁/WAL、领取及回执延迟；局部微测不代表端到端收益。验证命令、测试范围和环境边界见 [docs/VALIDATION.md](docs/VALIDATION.md)。

## 源码仓库边界

仓库保留源码、权威配置、合成测试夹具、锁文件和构建脚本。`target/`、`.cache/`、`dist/`、`state/`、运行数据与前端依赖/打包目录均可在对应构建或初始化步骤中生成，不纳入源码提交。清理这些目录后须先重新打包前端，再编译内嵌控制台的 Rust 程序。

示例中的 `rules.example.com`、文档保留地址和 `example/rules` 都是占位值。真实服务器、节点清单、账户凭据、证书私钥、部署日志及运行备份由部署方在仓库外管理；文档不保存具体部署记录。
