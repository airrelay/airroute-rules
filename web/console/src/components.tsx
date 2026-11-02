import { Alert, Badge, Button, Group, Loader, Text, Title } from "@mantine/core";
import type { ReactNode } from "react";
import { statusName } from "./api";
export function PageTitle({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <Group justify="space-between" align="flex-start" mb="xl">
      <div>
        <Title order={1}>{title}</Title>
        <Text c="dimmed" mt={8} size="sm">
          {description}
        </Text>
      </div>
      {action}
    </Group>
  );
}
export function StateBadge({ state }: { state: string }) {
  return (
    <Badge
      variant="light"
      radius="sm"
      color={
        state === "complete" || state === "decided"
          ? "green"
          : state === "failed" || state === "unknown"
            ? "red"
            : "blue"
      }
    >
      {statusName(state)}
    </Badge>
  );
}
export function ErrorBox({ error }: { error: Error | null | undefined }) {
  return error ? (
    <Alert color="red" mb="md" title="操作未完成">
      {error.message}
    </Alert>
  ) : null;
}
export function Empty({ children }: { children: ReactNode }) {
  return (
    <Text c="dimmed" ta="center" py={48}>
      {children}
    </Text>
  );
}
export function PageLoading({title}:{title:string}) {
  return <><Title order={1} mb="xl">{title}</Title><Group role="status" gap="sm"><Loader size="sm"/><Text c="dimmed">正在加载…</Text></Group></>;
}
export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>;
}
export function Refresh({ onClick }: { onClick: () => void }) {
  return (
    <Button variant="default" onClick={onClick}>
      刷新
    </Button>
  );
}
