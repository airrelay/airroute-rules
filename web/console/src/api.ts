import { useQuery } from "@tanstack/react-query";
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const r = await fetch("/api/" + path, {
    credentials: "same-origin",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    method: body === undefined ? "GET" : "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  if (!r.ok) {
    const value = await r.json().catch(() => ({ error: r.statusText }));
    throw new ApiError(r.status, value.error ?? r.statusText);
  }
  if (r.status === 204) return undefined as T;
  return r.json();
}
export function useApi<T>(path: string, enabled = true, interval: number | ((data:T|undefined)=>number|false) = 10000) {
  return useQuery<T, ApiError>({
    queryKey: [path],
    queryFn: ({signal}) => api<T>(path,undefined,signal),
    retry: false,
    staleTime: 2000,
    refetchInterval: typeof interval === "function" ? (query) => interval(query.state.data) : interval,
    enabled,
  });
}
export type Json = Record<string, unknown>;
export interface Rule {
  kind: string;
  value: string;
  modifiers: string[];
}
export interface Conflict {
  key: string;
  fingerprint: string;
  revision: number;
  kind: string;
  subject: string;
  reason: string;
  payload: {
    collection?: string;
    rule?: Rule;
    regions?: string[];
    ranges?: string[][];
    targets?: string[];
    [key: string]: unknown;
  };
  status: string;
  updated: number;
}
export interface NodeInfo {
  id: string;
  name: string;
  region: string;
  asn: number;
  capabilities: string[];
  disabled: boolean;
  connected: boolean;
  last_seen: number | null;
  completed_tasks?: number;
  running_tasks?: number;
  last_completed_at?: number | null;
  concurrency_limit?: number | null;
  effective_concurrency?: number;
  ipv4_supported?: boolean | null;
  ipv6_supported?: boolean | null;
  network_checked?: number | null;
}
export interface BuildInfo {
  id: string;
  status: string;
  started: number;
  finished: number | null;
  release: string | null;
  progress: {stage:number;stages:number;label:string;detail:string;completed:number;total:number|null;unit:string;bytes_received:number|null;bytes_total:number|null;updated:number}|null;
  summary: {
    targets: number;
    rules: number;
    cn_domain_rules: number;
    domain_quarantines: number;
    geography: {
      regions: Record<string, number>;
      active_required_groups: number;
    };
    incremental?: { new?: number; changed?: number; reused?: number; semantic_writes?: number; sync_pending?: boolean };
    observation_cutoff?: number;
    observations?: number;
    ip_library_ranges?: number;
  } | null;
  error: string | null;
}
export interface Overview {
  cases: Record<string, number>;
  jobs: Record<string, number>;
  domain_facts: number;
  current_release: string | null;
  nodes: NodeInfo[];
  builds: BuildInfo[];
}
export interface Collection {
  id: string;
  name: string;
  type: string;
  scope: string;
  sources: { source_id: string; selection: string }[];
  members: string[];
  projected_members: { id: string; domain_value_pattern: string }[];
  count: number | null;
}
export const regions = [
  ["cn-geo", "中国大陆"],
  ["us", "美国"],
  ["europe", "欧洲"],
  ["southeast-asia", "东南亚"],
  ["hk-mo", "港澳"],
  ["tw", "台湾"],
  ["northeast-asia", "东北亚"],
  ["south-asia", "南亚"],
  ["central-asia", "中亚"],
  ["west-asia", "西亚"],
  ["ru", "俄罗斯"],
  ["north-america-other", "北美其他"],
  ["latin-america-caribbean", "拉美与加勒比"],
  ["oceania", "大洋洲"],
  ["africa", "非洲"],
  ["antarctica", "南极"],
].map(([value, label]) => ({ value, label }));
export const regionName = (r: string) =>
  r === "any" ? "通用出口" : regions.find((v) => v.value === r)?.label ?? r;
export const number = (n: number | undefined | null) =>
  n == null ? "—" : n.toLocaleString("zh-CN");
export const time = (t: number | undefined | null) =>
  t ? new Date(t * 1000).toLocaleString("zh-CN", { hour12: false }) : "—";
export const statusName = (s: string) =>
  ({
    complete: "已完成",
    running: "执行中",
    failed: "失败",
    deferred: "输入已变化，等待重建",
    "needs-review": "待补证",
    "blocked-target": "待选目标",
    "needs-active": "待观测",
    "evidence-ready": "已有观测",
    decided: "历史决定",
    inactive: "已退出",
    pending: "排队中",
    queued: "待执行",
    scheduled: "重试等待",
    partial: "已观测，待补充",
    "waiting-node": "等待节点",
    "waiting-capability": "等待可用能力",
    "awaiting-target": "待可用目标",
    leased: "执行中",
    unknown: "结果不确定",
    obsolete: "已失效",
    cooldown: "本轮结束，冷却中",
  })[s] ?? s;
