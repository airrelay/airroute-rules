import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from "@tanstack/react-query";
import {
  MantineProvider,
  Button,
  Drawer,
  Modal,
  Pagination,
  PasswordInput,
  Stack,
  Text,
  Title,
  Loader,
  createTheme,
} from "@mantine/core";
import {
  IconLayoutDashboard,
  IconListDetails,
  IconRadar,
  IconActivity,
  IconBrandGithub,
  IconVersions,
  IconArrowUpRight,
} from "@tabler/icons-react";
import "@mantine/core/styles.css";
import "./styles.css";
import { api, useApi } from "./api";
import {
  OverviewPage,
  CataloguePage,
  BuildsPage,
} from "./pages";
import { ErrorBox } from "./components";
import { ProbePage } from "./resources";
import { GithubPage } from "./github";
import { AuditPage } from "./audit";
import { normalizeAuditHash } from "./audit-api";

const theme = createTheme({
  primaryColor: "blue",
  fontFamily:
    '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif',
  defaultRadius: "sm",
  headings: {
    fontWeight: "600",
    sizes: {
      h1: { fontSize: "1.5rem" },
      h2: { fontSize: "1.0625rem" },
      h3: { fontSize: "0.9375rem" },
    },
  },
  colors: {
    blue: [
      "#F4FAFF",
      "#E1EEFF",
      "#C3DEFF",
      "#98C6FF",
      "#65A9FF",
      "#318CFF",
      "#007AFF",
      "#0066D6",
      "#005BBD",
      "#0A2156",
    ],
  },
  components: {
    Drawer:Drawer.extend({defaultProps:{closeButtonProps:{'aria-label':'关闭'}}}),
    Modal:Modal.extend({defaultProps:{closeButtonProps:{'aria-label':'关闭'}}}),
    Pagination:Pagination.extend({defaultProps:{getControlProps:control=>({'aria-label':({first:'第一页',last:'最后一页',next:'下一页',previous:'上一页'})[control]})}}),
    Button: Button.extend({
      defaultProps: { size: "sm" },
      styles: { root: { fontWeight: 600, minHeight: 36 } },
    }),
  },
});
const pages = [
  {
    id: "overview",
    label: "概览",
    icon: IconLayoutDashboard,
    Page: OverviewPage,
  },
  {
    id: "catalogue",
    label: "规则目录",
    icon: IconListDetails,
    Page: CataloguePage,
  },
  {
    id: "audit",
    label: "规则核查",
    icon: IconActivity,
    Page: AuditPage,
  },
  { id: "probes", label: "探测资源", icon: IconRadar, Page: ProbePage },
  { id: "builds", label: "构建版本", icon: IconVersions, Page: BuildsPage },
  { id: "github", label: "GitHub 发布", icon: IconBrandGithub, Page: GithubPage },
];
function App() {
  const [page, setPage] = useState(() => normalizeAuditHash(location.hash).slice(1).split('?')[0] || "overview");
  useEffect(() => {
    const change = () => {
      const normalized=normalizeAuditHash(location.hash);
      if(normalized!==location.hash)history.replaceState(null,'',normalized);
      setPage(normalized.slice(1).split('?')[0] || "overview");
    };
    change();
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  const session = useApi<{authenticated:boolean}>("session",true,30000);
  const [token, setToken] = useState("");
  const [error, setError] = useState<Error | null>(null);
  const [pending, setPending] = useState(false);
  const client = useQueryClient();
  async function login() {
    setPending(true);
    setError(null);
    try {
      await api("login", { token });
      setToken("");
      await client.invalidateQueries();
    } catch (e) {
      setError(e as Error);
    } finally {
      setPending(false);
    }
  }
  if (session.isLoading)
    return (
      <div className="loading">
        <Loader />
        <Text mt="md">连接控制中心</Text>
      </div>
    );
  if (session.error?.status === 401)
    return (
      <div className="login">
        <div className="login-form">
          <div className="brand-mark">A</div>
          <Title order={1}>AirRoute Rules</Title>
          <Text c="dimmed" mt={8} mb={28}>
            登录规则构建控制中心
          </Text>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void login();
            }}
          >
            <Stack>
              <PasswordInput
                autoFocus
                label="管理员令牌"
                autoComplete="current-password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                description="使用 data/admin-token 文件或已配置的管理员令牌。"
              />
              <ErrorBox error={error} />
              <Button type="submit" loading={pending} disabled={!token}>
                登录
              </Button>
            </Stack>
          </form>
        </div>
      </div>
    );
  if (session.error)
    return (
      <div className="loading">
        <ErrorBox error={session.error} />
        <Button onClick={() => session.refetch()}>重试连接</Button>
      </div>
    );
  const current = pages.find((p) => p.id === page) ?? pages[0];
  const Page = current.Page;
  return (
    <div className="app">
      <aside className="sidebar">
        <a
          className="brand"
          href="#overview"
          onClick={() => setPage("overview")}
        >
          <span className="brand-mark small">A</span>
          <div>
            AirRoute<span>Rules Console</span>
          </div>
        </a>
        <nav aria-label="主导航">
          {pages.map((p) => (
            <a
              key={p.id}
              href={`#${p.id}`}
              aria-current={p.id === current.id ? "page" : undefined}
              onClick={() => setPage(p.id)}
            >
              <p.icon size={19} stroke={1.6} />
              {p.label}
            </a>
          ))}
        </nav>
        <div className="sidebar-footer">
          <Text size="xs" c="dimmed" mt={8}>
            Rust controller · v0.2.0
          </Text>
          <a href="https://www.airroute.dev" target="_blank" rel="noreferrer">
            AirRoute <IconArrowUpRight size={14} />
          </a>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span>
            规则数据工作台 <span className="slash">/</span> {current.label}
          </span>
          <Button
            variant="subtle"
            size="compact-sm"
            onClick={async () => {
              await api("logout", {});
              await client.resetQueries();
            }}
          >
            退出登录
          </Button>
        </header>
        <main>
          <Page />
        </main>
        <footer>每日生成规则 · 观测用于下一次构建</footer>
      </div>
    </div>
  );
}
const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 5000 } },
});
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <MantineProvider theme={theme}>
        <App />
      </MantineProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
