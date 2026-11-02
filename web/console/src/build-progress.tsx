import { useEffect,useState } from 'react';
import { Alert,Group,Progress,Stack,Text } from '@mantine/core';
import { number,time,type BuildInfo } from './api';
const labels=['准备构建','读取来源','地区核查','构建规则','写入文件','完整验证','切换版本'];
const bytes=(n:number)=>n>=1048576?`${(n/1048576).toFixed(1)} MiB`:`${number(Math.round(n/1024))} KiB`;
export function BuildProgress({build}:{build:BuildInfo}){
 const [clock,setClock]=useState(Date.now());const running=build.status==='running';
 useEffect(()=>{if(!running)return;const timer=setInterval(()=>setClock(Date.now()),1000);return()=>clearInterval(timer);},[running]);
 const p=build.progress;const complete=build.status==='complete';const failed=build.status==='failed';const deferred=build.status==='deferred';const color=failed?'red':deferred?'yellow':complete?'green':'blue';
 const elapsed=Math.max(0,Math.floor(((build.finished??clock/1000)-build.started)));
 return <Alert color={color} mb="xl" title={complete?'构建已完成':failed?'构建已停止':deferred?'输入发生变化，等待重建':'正在构建'}><Stack gap="sm"><Group justify="space-between"><Text fw={600}>{p?`步骤 ${p.stage} / ${p.stages} · ${p.label}`:running?'等待构建进程报告阶段':'此历史记录未保存阶段进度'}</Text><Text size="sm">{elapsed>=60?`${Math.floor(elapsed/60)} 分 ${elapsed%60} 秒`:`${elapsed} 秒`}</Text></Group><Progress aria-label="已完成构建步骤" value={complete?100:p?Math.max(0,p.stage-1)/p.stages*100:0} color={color}/><Group gap="xs" wrap="wrap">{labels.map((label,index)=><Text key={label} size="xs" c={p&&index+1===p.stage?color:'dimmed'} fw={p&&index+1===p.stage?600:400}>{index+1}. {label}</Text>)}</Group><Text size="sm">{complete?'规则已通过完整验证，当前版本已切换。':p?.detail??'读取构建配方与运行设置。'}</Text>{p&&!complete&&p.unit&&<Text size="sm">{number(p.completed)}{p.total!==null?` / ${number(p.total)}`:''} {p.unit}</Text>}{p?.bytes_received!=null&&running&&<Text size="sm">已接收 {bytes(p.bytes_received)}{p.bytes_total!=null?` / ${bytes(p.bytes_total)}`:''}</Text>}{p&&<Text size="xs" c="dimmed">最新进度：{time(p.updated)}</Text>}{(failed||deferred)&&<Text size="sm" c="red" style={{overflowWrap:'anywhere'}}>{build.error}</Text>}</Stack></Alert>;
}
