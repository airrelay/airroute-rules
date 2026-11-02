import { useState } from "react";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Drawer,
  Group,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import {
  api,
  useApi,
  number,
  time,
  regionName,
  type Overview,
  type BuildInfo,
  type Collection,
  type Json,
} from "./api";
import {
  PageTitle,
  PageLoading,
  StateBadge,
  ErrorBox,
  Empty,
  JsonBlock,
} from "./components";
import { BuildProgress } from './build-progress';

export function OverviewPage() {
  const q = useApi<Overview>("overview");
  const builds=useApi<BuildInfo[]>("builds?compact=true",true,data=>data?.some(b=>b.status==='running')?1000:15000);
  const running=builds.data?.find(b=>b.status==='running');
  const d = q.data;
  const latest = (builds.data??d?.builds)?.find((b) => b.status === "complete");
  const geo = latest?.summary?.geography;
  const client = useQueryClient();
  const build = useMutation({
    mutationFn: () => api("builds", {}),
    onSuccess: () => client.invalidateQueries(),
  });
  if(q.isPending) return <PageLoading title="规则构建概览"/>;
  return (
    <>
      <PageTitle
        title="规则构建概览"
        description="每日固定输入生成规则；有效分歧按确定性策略输出，新观测在下一次构建使用。"
        action={
          <Button
            onClick={() => build.mutate()}
            loading={
              build.isPending || !!running
            }
          >
            运行全量构建
          </Button>
        }
      />
      <ErrorBox error={q.error ?? builds.error ?? build.error} />
      {running&&<BuildProgress build={running}/>}
      <div className="metrics">
        {[
          [
            "最终规则集",
            number(latest?.summary?.targets),
            "四类目录，统一分发",
          ],
          ["发现域名", number(d?.domain_facts), "用于发现可测目标"],
          [
            "地区待证事项",
            number(geo?.active_required_groups),
            "完整输出，按需继续补证",
          ],
          [
            "在线探测节点",
            number(
              d?.nodes.filter(
                (n) =>
                  !n.disabled && n.connected &&
                  n.last_seen &&
                  Date.now() / 1000 - n.last_seen < 120,
              ).length,
            ),
            "按能力共享观测任务",
          ],
        ].map(([label, value, note]) => (
          <div className="metric" key={label}>
            <Text size="sm" c="dimmed">
              {label}
            </Text>
            <strong>{value}</strong>
            <Text size="xs" c="dimmed">
              {note}
            </Text>
          </div>
        ))}
      </div>
      <div className="split">
        <section>
          <Title order={2} mb="md">
            地区争议分布
          </Title>
          <Text size="sm" c="dimmed" mb="md">
            按候选地区统计，一项争议可参与多个地区。
          </Text>
          {geo ? (
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>地区</Table.Th>
                  <Table.Th ta="right">待证组</Table.Th>
                  <Table.Th>参与占比</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {Object.entries(geo.regions)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([r, n]) => (
                    <Table.Tr key={r}>
                      <Table.Td>{regionName(r)}</Table.Td>
                      <Table.Td ta="right" className="mono">
                        {number(n)}
                      </Table.Td>
                      <Table.Td>
                        <div className="bar">
                          <i
                            style={{
                              width: `${(100 * n) / Math.max(...Object.values(geo.regions))}%`,
                            }}
                          />
                        </div>
                      </Table.Td>
                    </Table.Tr>
                  ))}
              </Table.Tbody>
            </Table>
          ) : (
            <Empty>首次构建后显示完整统计</Empty>
          )}
        </section>
        <section>
          <Title order={2} mb="md">
            最近构建
          </Title>
          {d?.builds.length ? (
            <Stack gap="sm">
              {d.builds.slice(0, 5).map((b) => (
                <div className="build-row" key={b.id}>
                  <Group justify="space-between">
                    <Text size="sm">{time(b.started)}</Text>
                    <StateBadge state={b.status} />
                  </Group>
                  <Text size="xs" c="dimmed" mt={8}>
                    {b.summary
                      ? `${number(b.summary.rules)} 条规则${b.summary.incremental?.sync_pending ? " · 补证需求后台同步" : b.summary.incremental?.reused != null ? ` · 复用 ${number(b.summary.incremental.reused)} 项争议` : ""}`
                      : (b.error ?? "正在获取、清洗与验证完整输入")}
                  </Text>
                  {b.release && (
                    <Text size="xs" className="mono" mt={8}>
                      {b.release}
                    </Text>
                  )}
                </div>
              ))}
            </Stack>
          ) : (
            <Empty>还没有构建记录</Empty>
          )}
          <div className="note">
            <Text size="sm" fw={600}>
              有效版本持续可用
            </Text>
            <Text size="sm" c="dimmed" mt={6}>
              必需来源或验证失败时保留上次完整版本。DNS
              变化与探测完成不会直接改写服务归属。
            </Text>
          </div>
        </section>
      </div>
    </>
  );
}
const collectionName = (r: Collection) => r.name;
export function CataloguePage() {
  const q = useApi<{ items: Collection[]; sources: Json; official_endpoints: Json }>("catalogue");
  const [search, setSearch] = useState("");
  const [type, setType] = useState<string | null>(null);
  const [selected, setSelected] = useState<Collection | null>(null);
  const rows =
    q.data?.items.filter(
      (r) =>
        (!type || r.type === type) &&
        `${r.id} ${collectionName(r)}`.toLowerCase().includes(search.toLowerCase()),
    ) ?? [];
  if(q.isPending) return <PageLoading title="规则目录与来源"/>;
  return (
    <>
      <PageTitle
        title="规则目录与来源"
        description="规则集与 IP 库由同一构建生成，来源配方统一维护。"
        action={<Button component="a" href="/api/ip-library" variant="default">IP 库下载</Button>}
      />
      <ErrorBox error={q.error} />
      <Group mb="lg">
        <TextInput
          placeholder="搜索名称或规则路径"
          aria-label="搜索规则"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, maxWidth: 440 }}
        />
        <Select
          placeholder="所有类别"
          aria-label="规则类别"
          clearable
          data={[
            { value: "region", label: "国家地区" },
            { value: "category", label: "分类服务" },
            { value: "provider", label: "服务商与产品" },
            { value: "special", label: "特殊用途" },
          ]}
          value={type}
          onChange={setType}
        />
        <Text size="sm" c="dimmed">
          {number(rows.length)} 个集合
        </Text>
      </Group>
      <div className="table-scroll">
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>规则集</Table.Th>
              <Table.Th>路径</Table.Th>
              <Table.Th>原料 / 成员</Table.Th>
              <Table.Th ta="right">条数</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Button
                    variant="subtle"
                    size="compact-sm"
                    onClick={() => setSelected(r)}
                  >
                    {collectionName(r)}
                  </Button>
                </Table.Td>
                <Table.Td className="mono">{r.id}</Table.Td>
                <Table.Td>
                  {r.sources.length} / {r.members.length + r.projected_members.length}
                </Table.Td>
                <Table.Td ta="right" className="mono">
                  {number(r.count)}
                </Table.Td>
                <Table.Td>
                  <Button
                    component="a"
                    href={`/api/rules/${r.id}.list`}
                    variant="default"
                    size="compact-xs"
                  >
                    下载
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </div>
      <Drawer
        opened={!!selected}
        onClose={() => setSelected(null)}
        position="right"
        size="lg"
        title={selected?collectionName(selected):undefined}
      >
        <Text mb="lg">{selected?.scope}</Text>
        <Title order={3} mb="sm">
          构建配方
        </Title>
        <JsonBlock value={selected} />
        <Title order={3} my="md">
          上游仓库与官方端点参考
        </Title>
        <JsonBlock value={{repositories:q.data?.sources,official_endpoints:q.data?.official_endpoints}} />
      </Drawer>
    </>
  );
}
export function BuildsPage() {
  const q = useApi<BuildInfo[]>("builds?compact=true",true,data=>data?.some(b=>b.status==='running')?1000:15000);
  const client = useQueryClient();
  const start = useMutation({
    mutationFn: () => api("builds", {}),
    onSuccess: () => client.invalidateQueries(),
  });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const full=useApi<BuildInfo[]>("builds",!!selectedId,data=>data?.some(b=>b.status==='running')?1000:15000);
  const selected=full.data?.find(b=>b.id===selectedId)??q.data?.find(b=>b.id===selectedId)??null;
  const running=q.data?.find(b=>b.status==='running');
  if(q.isPending) return <PageLoading title="构建与版本"/>;
  return (
    <>
      <PageTitle
        title="构建与版本"
        description="完整输入、完整验证、原子切换。失败构建不会替换有效版本。"
        action={
          <Button
            onClick={() => start.mutate()}
            loading={
              start.isPending || q.data?.some((b) => b.status === "running")
            }
          >
            运行全量构建
          </Button>
        }
      />
      <ErrorBox error={q.error ?? start.error ?? full.error} />
      {start.isPending&&!running&&<Alert mb="lg">正在提交构建任务…</Alert>}
      {running&&<BuildProgress build={running}/>}
      <div className="table-scroll">
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>开始时间</Table.Th>
              <Table.Th>状态</Table.Th>
              <Table.Th>版本</Table.Th>
              <Table.Th>规则数</Table.Th>
              <Table.Th>补证同步</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.data?.map((b) => (
              <Table.Tr key={b.id}>
                <Table.Td>{time(b.started)}</Table.Td>
                <Table.Td>
                  <StateBadge state={b.status} />
                </Table.Td>
                <Table.Td className="mono">{b.release ?? "—"}</Table.Td>
                <Table.Td>{number(b.summary?.rules)}</Table.Td>
                <Table.Td>
                  {b.summary?.incremental?.sync_pending
                    ? "后台同步"
                    : b.summary?.incremental?.new != null && b.summary.incremental.changed != null
                    ? `新增 ${b.summary.incremental.new} / 变化 ${b.summary.incremental.changed}`
                    : "—"}
                </Table.Td>
                <Table.Td>
                  <Button variant="subtle" onClick={() => setSelectedId(b.id)}>
                    详情
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </div>
      <Drawer
        opened={!!selected}
        onClose={() => setSelectedId(null)}
        position="right"
        size="lg"
        title="构建记录"
      >
        {selected&&<BuildProgress build={selected}/>}
        <JsonBlock value={selected} />
      </Drawer>
    </>
  );
}
