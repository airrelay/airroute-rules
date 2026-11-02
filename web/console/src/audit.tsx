import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Accordion, Alert, Badge, Button, Checkbox, Drawer, Group, Loader, Modal,
  MultiSelect, Pagination, Select, Stack, Table, Tabs, Text, TextInput, Title,
} from '@mantine/core';
import { IconArrowRight, IconSearch, IconX } from '@tabler/icons-react';
import { api, useApi, number, time, regionName, regions, type BuildInfo, type NodeInfo } from './api';
import { PageTitle, Empty, ErrorBox, JsonBlock } from './components';
import {
  auditHref, auditPage, auditPageSize, auditParams, auditQuery, auditView, normalizeAuditHash, auditDetailHref, auditCloseDetailHref,
  type AuditCaseLink, type AuditIssue, type AuditRecord, type AuditResponse,
  type AuditTask, type AuditView,
} from './audit-api';

const issueCategories=[
  {value:'measurable',label:'需要探测补充材料'},
  {value:'sources',label:'来源与规则分歧'},
  {value:'gaps',label:'覆盖缺口'},
  {value:'all',label:'完整问题清单'},
];
const taskRanges=[{value:'current',label:'当前任务'},{value:'ended',label:'本轮已结束'},{value:'all',label:'全部任务（含历史）'}];
const purposes=[{value:'all',label:'全部用途'},{value:'business',label:'业务探测'},{value:'discovery',label:'仅辅助目标发现'}];
const issueStates:Record<string,string>={
  'awaiting-target':'缺少探测 IP',processing:'任务处理中',queued:'任务待执行',
  unconfirmed:'提交待核实',cooldown:'本轮冷却',returned:'本轮已有回传',
  'not-scheduled':'不安排主动探测',syncing:'需求同步中',historical:'历史问题',
};
const taskStates:Record<string,string>={queued:'待执行',processing:'处理中',unconfirmed:'状态待核实',cooldown:'本轮冷却',ended:'本轮已结束',obsolete:'已退出'};
const recordStates:Record<string,string>={returned:'有回传的执行记录',inflight:'处理中',unconfirmed:'提交待核实',reused:'复用已有结果','not-executed':'已证明未执行','legacy-history':'历史身份待核实'};
const phaseNames:Record<string,string>={reserved:'已分配，待开始',started:'已进入执行阶段',prepared:'准备提交',sending:'正在提交',remote:'远端测量中',unknown:'状态待核实',cooldown:'本轮执行机会已耗尽',delayed:'等待可执行时间',pending:'待分配',complete:'本轮已结束',obsolete:'已退出'};
const kindNames:Record<string,string>={dns:'DNS',traceroute:'Traceroute','anycast-validation':'端点补充材料','endpoint-reachability':'端点补充材料',geolocation:'地区来源分歧','domain-policy':'域名规则边界','coverage-gap':'覆盖缺口','domain-observation':'临时域名探测','manual-ip':'临时 IP 探测','target-discovery':'辅助目标发现'};
function stateNames(view:AuditView){return view==='issues'?issueStates:view==='tasks'?taskStates:recordStates;}
function State({value,view}:{value:string;view:AuditView}){
  const color=['returned','ended'].includes(value)?'green':['unconfirmed','cooldown','legacy-history'].includes(value)?'orange':'blue';
  return <Badge variant="light" radius="sm" color={color}>{stateNames(view)[value]??value}</Badge>;
}
function LoadingLine({text='正在加载列表…'}:{text?:string}){
  return <Group gap="xs" role="status" py="lg"><Loader size="xs"/><Text size="sm" c="dimmed">{text}</Text></Group>;
}
function localDateTime(epoch:string|null){
  if(!epoch)return '';
  const d=new Date(Number(epoch)*1000),two=(n:number)=>String(n).padStart(2,'0');
  if(!Number.isFinite(d.getTime()))return '';
  return `${d.getFullYear()}-${two(d.getMonth()+1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}`;
}
function epochTime(value:string){return value?String(Math.floor(new Date(value).getTime()/1000)):'';}
const subjectOf=(links:AuditCaseLink[],key:string)=>links.find(c=>c.key===key)?.subject??key;
const freshness=(record:AuditRecord)=>record.fresh==null?'未标有效期':record.fresh?'仍在有效期内':'已过有效期';
function object(value:unknown):Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:{};}
function IssueTargetDetails({issue,historical}:{issue:AuditIssue;historical:boolean}){
  const payload=issue.payload??{},plan=object(payload.sample_plan);
  const evidence=object(issue.target_evidence??payload.target_evidence);
  const ranges=(Array.isArray(payload.ranges)?payload.ranges:[]).filter((r):r is string[]=>Array.isArray(r)&&typeof r[0]==='string'&&typeof r[1]==='string');
  const bounded=plan.strategy==='bgp-bounded-v1'||issue.targets.some(ip=>object(evidence[ip]).kind==='sampled-candidate');
  return <>
    {(typeof payload.bgp_prefix==='string'||ranges.length>0)&&<section aria-label="问题的 BGP 分组与实际范围"><Title order={3} mb="xs">BGP 分组与实际范围</Title>
      {typeof payload.bgp_prefix==='string'&&<Text size="sm">BGP 父前缀：{payload.bgp_prefix}</Text>}
      {ranges.slice(0,8).map((r,i)=><Text key={i} size="sm" className="mono">{r[0]===r[1]?r[0]:`${r[0]} – ${r[1]}`}</Text>)}
      {ranges.length>8&&<Text size="xs" c="dimmed">另有 {number(ranges.length-8)} 个范围，见本轮问题资料。</Text>}
      <Text size="xs" c="dimmed" mt={4}>{plan.strategy==='bgp-bounded-v1'?'本轮按 BGP 边界内的同质连续子范围组织；不跨地址洞或合并不同语义的子范围。':'该版本按其记录中的实际范围核查。'} BGP 父前缀用于组织，不表示整段已被测量或已确认地区。</Text>
    </section>}
    {issue.targets.length>0&&<section aria-label="探测 IP 的候选选择依据"><Title order={3} mb="xs">候选选择依据</Title>
      <Text size="xs" c="dimmed" mb="sm">{issue.target_evidence_is_live?'当前同范围的候选选择依据':'该构建快照保留的候选选择依据'}{historical&&issue.target_evidence_is_live?'；不表示这些目标在该历史构建时已经取得。':'。'}</Text>
      <Table><Table.Thead><Table.Tr><Table.Th>精确目标 IP</Table.Th><Table.Th>来源</Table.Th><Table.Th>观察时间 / 有效期</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{issue.targets.map(ip=>{
        const e=object(evidence[ip]),sampled=e.kind==='sampled-candidate';
        const label=sampled?'范围抽样选取的 IP':e.kind==='dns-answer'?'已有 DNS 候选（未证明端点响应）':e.kind==='endpoint-response'?'已有端点响应':'该快照未附此候选的来源';
        const observed=typeof e.observed==='number'&&e.observed>0?e.observed:null,until=typeof e.valid_until==='number'&&e.valid_until>0?e.valid_until:null;
        return <Table.Tr key={ip}><Table.Td className="mono">{ip}</Table.Td><Table.Td><Text size="sm">{label}</Text>{typeof e.source==='string'&&<Text size="xs" c="dimmed">{e.source}</Text>}</Table.Td><Table.Td><Text size="xs" c="dimmed">{sampled?'选择依据不含响应观察时间或 TTL；实际响应见执行记录。':observed?`观察于 ${time(observed)}${until?`；有效至 ${time(until)}`:''}`:'没有可核验的观察时钟'}</Text></Table.Td></Table.Tr>;
      })}</Table.Tbody></Table>
    </section>}
    {bounded&&<Text size="sm" c="dimmed">本组最多三个固定候选，优先使用已有 DNS 或端点依据，缺额才从本组精确 IPv4 范围选择；IPv6 不随机补地址。每个共享任务每轮最多三次实际执行机会，由自有节点与 Globalping 合计，不按节点重算；未决提交继续防重，不靠换候选或换任务 ID 绕过。</Text>}
  </>;
}
function legacyNotice(selector:string){
  const value=selector.replace(/^(source|state|kind|status):/,'');
  if(['failed','unknown'].includes(value))return '旧“需处理”已拆为“状态待核实”和“本轮冷却”。这里先展示当前任务，请按下方状态分别查看。';
  if(['build','manual'].includes(value))return '构建与人工临时探测现在共同归为业务探测；当前列表可能同时包含两种来源。';
  return '新分类与旧口径存在差异，已选择最接近的范围，可能包含其他类型；以下方当前筛选条件为准。';
}

function Summary({view,data,loading,error,selected,onState}:{
  view:AuditView;data?:AuditResponse<unknown>;loading:boolean;error:Error|null;
  selected:string;onState:(state:string)=>void;
}){
  const states=data?.states;
  const core=view==='tasks'?['queued','processing','unconfirmed','cooldown']:view==='records'?['returned','inflight','unconfirmed']:[];
  const keys=states?Array.from(new Set([...core,...Object.keys(states)])).filter(k=>(states[k]??0)>0||core.includes(k)||selected===k):[];
  return <section className="audit-summary" aria-label="当前筛选统计" aria-live="polite">
    <ErrorBox error={error}/>
    {loading&&!data?<Text size="sm" c="dimmed" role="status">正在加载统计，列表可独立查看…</Text>:<>
      <Group justify="space-between" mb={keys.length?'sm':0}>
        <Text size="sm">当前筛选：<strong>{number(data?.total)}</strong> {view==='issues'?'个规则问题':view==='tasks'?'个去重任务':'条记录'}</Text>
        <Text size="xs" c="dimmed">单位：{view==='issues'?'规则问题':view==='tasks'?'去重任务':'原尝试记录'}{data?.scope?.at?` · 统计于 ${time(data.scope.at)}`:''}</Text>
      </Group>
      {keys.length>0&&<div className="audit-counts">{keys.map(key=><button type="button" className="audit-count" key={key} aria-pressed={selected===key} onClick={()=>onState(selected===key?'':key)}><strong>{number(states?.[key]??0)}</strong><span>{stateNames(view)[key]??key}</span></button>)}</div>}
    </>}
  </section>;
}

export function AuditPage(){
  const [hash,setHash]=useState(()=>normalizeAuditHash(location.hash));
  useEffect(()=>{const changed=()=>setHash(normalizeAuditHash(location.hash));window.addEventListener('hashchange',changed);return()=>window.removeEventListener('hashchange',changed);},[]);
  const params=auditParams(hash),view=auditView(params),page=auditPage(params);
  const [search,setSearch]=useState(params.get('q')??'');
  const [after,setAfter]=useState(()=>localDateTime(params.get('after')));
  const [before,setBefore]=useState(()=>localDateTime(params.get('before')));
  const [dateError,setDateError]=useState('');
  const [record,setRecord]=useState<AuditRecord|null>(null);
  const [manualOpened,setManualOpened]=useState(false);
  const [target,setTarget]=useState('');
  const [coverage,setCoverage]=useState(['us','europe']);
  const [refresh,setRefresh]=useState(false);
  const [candidate,setCandidate]=useState('');
  const client=useQueryClient();
  const searchParam=params.get('q')??'',afterParam=params.get('after'),beforeParam=params.get('before'),caseKey=params.get('case_key')??'',jobId=params.get('job_id')??'';
  useEffect(()=>{setSearch(searchParam);},[searchParam]);
  useEffect(()=>{setAfter(localDateTime(afterParam));setBefore(localDateTime(beforeParam));setDateError('');},[afterParam,beforeParam]);
  useEffect(()=>{setRecord(null);setCandidate('');},[view,caseKey,jobId]);
  function go(patch:Record<string,string|null>){location.hash=auditHref(params,patch);}
  function openIssue(key:string,buildId?:string|null){location.hash=auditDetailHref(params,'issues',key,buildId);}
  function openTask(id:string){location.hash=auditDetailHref(params,'tasks',id);}
  function closeDetail(kind:'issues'|'tasks'){location.hash=auditCloseDetailHref(params,kind);}
  function filter(patch:Record<string,string|null>){go({...patch,page:'1',legacy_filter:null});}
  const items=useApi<AuditResponse<AuditIssue|AuditTask|AuditRecord>>(auditQuery(view,params,'items'),true,view==='issues'&&params.get('build_id')?60000:10000);
  const shownBuild=view==='issues'?(params.get('build_id')||items.data?.build_id):null;
  const summary=useApi<AuditResponse<unknown>>(auditQuery(view,params,'summary',shownBuild),true,view==='issues'&&params.get('build_id')?60000:30000);
  const compatibleSummary=view!=='issues'||!items.data?.build_id||!summary.data?.build_id||items.data.build_id===summary.data.build_id;
  const builds=useApi<BuildInfo[]>('builds?compact=true',view==='issues',60000);
  const nodes=useApi<NodeInfo[]>('nodes',view!=='issues',30000);
  const nodeName=(node:string|null)=>node?(nodes.data?.find(n=>n.id===node)?.name||node.replace(/^globalping:/,'')):'尚未分配';
  const observer=(executor:string,node:string|null)=>executor==='globalping'?`Globalping${node?` · ${nodeName(node)}`:''}`:executor==='self'?nodeName(node):'尚未分配';
  const issue= view==='issues'&&caseKey ? (items.data?.items as AuditIssue[]|undefined)?.find(c=>c.key===caseKey):undefined;
  const task= view==='tasks'&&jobId ? (items.data?.items as AuditTask[]|undefined)?.find(j=>j.id===jobId):undefined;
  const observe=useMutation({mutationFn:()=>api('observations',{target,regions:coverage,refresh,reason:'operator requested temporary measurement'}),onSuccess:()=>{setManualOpened(false);void client.invalidateQueries({predicate:q=>String(q.queryKey[0]).startsWith('audit/')});go({view:'tasks',range:'current',purpose:'business',case_key:null,job_id:null,q:null,state:null,page:'1'});}});
  const saveTarget=useMutation({mutationFn:()=>api('targets',{key:issue?.key,fingerprint:issue?.fingerprint,targets:candidate.split(/[\s,]+/).filter(Boolean)}),onSuccess:()=>{setCandidate('');void client.invalidateQueries({predicate:q=>String(q.queryKey[0]).startsWith('audit/')});}});
  const rows=items.data?.items??[];
  const total=compatibleSummary?summary.data?.total:undefined;
  const pageCount=total==null?Math.max(page,page+(rows.length===auditPageSize?1:0)):Math.max(1,Math.ceil(total/auditPageSize));
  const names=stateNames(view);
  const selectedState=params.get('state')??'';
  const buildOptions=[{value:'',label:'最新成功构建'},...(builds.data??[]).filter(b=>b.status==='complete').map(b=>({value:b.id,label:`${time(b.finished??b.started)} · ${b.id.slice(0,8)}`}))];
  if(params.get('build_id')&&!buildOptions.some(b=>b.value===params.get('build_id')))buildOptions.push({value:params.get('build_id')!,label:`构建 ${params.get('build_id')!.slice(0,8)}`});
  function relatedTasks(key:string){go({view:'tasks',case_key:key,job_id:null,purpose:'all',range:'all',state:null,q:null,page:'1'});}
  function relatedRecords(key:string|null,id:string|null){go({view:'records',case_key:key,job_id:id,purpose:'all',state:null,q:null,page:'1'});}
  function relatedIssue(c:AuditCaseLink){
    openIssue(c.key,caseKey===c.key?params.get('build_id'):null);
  }
  function issueLinks(links:AuditCaseLink[]){
    if(!links.length)return <Text size="xs" c="dimmed">历史关联已保留；当前没有规则问题</Text>;
    return <Stack gap={2}>{links.map(c=>['target-discovery','domain-observation','manual-ip'].includes(c.kind)?<Text key={c.key} size="xs" c="dimmed">{c.kind==='target-discovery'?'辅助目标发现':'人工临时探测'}{c.current?'':' · 历史'}</Text>:<Button key={c.key} variant="subtle" size="compact-xs" className="audit-link" onClick={()=>relatedIssue(c)}>{c.subject||c.key}{c.current?'':' · 历史'}</Button>)}</Stack>;
  }
  function applySearch(e:React.FormEvent){e.preventDefault();filter({q:search.trim()});}
  return <div className="audit-page">
    <PageTitle title="规则核查" description="规则问题 → 探测任务 → 执行记录。任务有回传，不等于规则问题已解决。" action={<Button onClick={()=>{setTarget('');setRefresh(false);observe.reset();setManualOpened(true);}}>临时探测</Button>}/>
    <Tabs value={view} onChange={value=>value&&go({view:value})} mb="lg"><Tabs.List aria-label="规则核查视图"><Tabs.Tab value="issues">规则问题</Tabs.Tab><Tabs.Tab value="tasks">探测任务</Tabs.Tab><Tabs.Tab value="records">执行记录</Tabs.Tab></Tabs.List></Tabs>
    <Text size="sm" c="dimmed" mb="lg">{view==='issues'?'规则哪里需要核查？本次输出采用什么依据？':view==='tasks'?'现在具体测什么？为什么测？卡在哪里？每行只算一个共享任务。':'谁尝试过？回传了什么？这些结果能用于哪里？'}</Text>
    {params.get('legacy_filter')&&<Alert mb="md" color="blue" withCloseButton onClose={()=>filter({legacy_filter:null})}>原筛选“{params.get('legacy_filter')}”：{legacyNotice(params.get('legacy_filter')!)}</Alert>}
    {(caseKey||jobId)&&<Group className="audit-context" mb="lg" gap="sm">
      {caseKey&&<><Text size="sm">仅查看关联问题：<span className="mono">{view==='tasks'?subjectOf((rows as AuditTask[]).flatMap(j=>j.cases??[]),caseKey):view==='records'?subjectOf((rows as AuditRecord[]).flatMap(r=>r.cases??[]),caseKey):issue?.subject??caseKey}</span></Text><Button variant="subtle" size="compact-xs" leftSection={<IconX size={13}/>} onClick={()=>filter({case_key:null})}>清除问题筛选</Button></>}
      {jobId&&<><Text size="xs" className="mono">任务 {jobId}</Text><Button variant="subtle" size="compact-xs" leftSection={<IconX size={13}/>} onClick={()=>filter({job_id:null})}>清除任务筛选</Button></>}
    </Group>}
    {view!=='issues'&&caseKey&&params.get('build_id')&&<Text size="xs" c="dimmed" mb="md">关联问题来自构建 {params.get('build_id')!.slice(0,8)}；下方展示该问题保留的跨版本任务或执行历史，不代表全部发生于该构建。</Text>}
    <Group className="audit-filters" mb="md" align="end">
      {view==='issues'?<>
        <Select label="问题类型" aria-label="核查记录类型" data={issueCategories} value={params.get('category')??'measurable'} onChange={value=>filter({category:value??'measurable',state:null})}/>
        <Select label="构建版本" aria-label="核查构建版本" data={buildOptions} value={params.get('build_id')??''} onChange={value=>filter({build_id:value,case_key:null,state:null})} searchable/>
      </>:<Select label="任务用途" aria-label="任务用途" data={purposes} value={params.get('purpose')??'all'} onChange={value=>filter({purpose:value??'all'})}/>}
      {view==='tasks'&&<Select label="状态范围" aria-label="任务状态范围" data={taskRanges} value={params.get('range')??'current'} onChange={value=>filter({range:value??'current',state:null})}/>}
      <Select label={view==='issues'?'材料进度':view==='tasks'?'任务状态':'回传情况'} aria-label="筛选状态" clearable placeholder="全部状态" value={selectedState||null} onChange={value=>filter({state:value})} data={Object.entries(names).map(([value,label])=>({value,label}))}/>
      <form className="audit-search" onSubmit={applySearch}><TextInput label={view==='issues'?'查找问题':'查找目标'} aria-label="查找规则核查记录" placeholder={view==='issues'?'IP、范围或规则对象':'域名、IP 或任务 ID'} value={search} onChange={e=>setSearch(e.currentTarget.value)} rightSection={search?<Button variant="subtle" size="compact-xs" aria-label="清除搜索" onClick={()=>{setSearch('');filter({q:null});}}><IconX size={13}/></Button>:undefined}/><Button type="submit" variant="default" leftSection={<IconSearch size={15}/>}>查找</Button></form>
    </Group>
    {view==='records'&&<form onSubmit={e=>{e.preventDefault();const a=epochTime(after),b=epochTime(before);if((a&&!Number.isFinite(Number(a)))||(b&&!Number.isFinite(Number(b)))||(a&&b&&Number(a)>Number(b))){setDateError('请填写有效时间，开始时间不能晚于结束时间。');return;}setDateError('');filter({after:a,before:b});}}><Group mb="md" align="end"><TextInput type="datetime-local" label="尝试建立时间，从" value={after} onChange={e=>setAfter(e.currentTarget.value)}/><TextInput type="datetime-local" label="至" value={before} onChange={e=>setBefore(e.currentTarget.value)}/><Button type="submit" variant="default">应用时间范围</Button>{(afterParam||beforeParam)&&<Button variant="subtle" onClick={()=>filter({after:null,before:null})}>全部时间</Button>}</Group>{dateError&&<Alert role="alert" color="red" mb="md">{dateError}</Alert>}</form>}
    {view==='issues'&&items.data?.build_id&&<Text size="xs" c="dimmed" mb="md">{items.data.historical?'历史构建':'本轮构建'} {items.data.build_id.slice(0,8)} · {time(items.data.built_at)}{items.data.observation_cutoff?` · 使用 ${time(items.data.observation_cutoff)} 前的观测快照`:''} · 完整清单 {number(compatibleSummary?summary.data?.full_total:undefined)} 项</Text>}
    <Summary view={view} data={compatibleSummary?summary.data:undefined} loading={summary.isPending||!compatibleSummary} error={summary.error} selected={selectedState} onState={state=>filter({state})}/>
    <ErrorBox error={items.error}/>
    {items.isPending?<LoadingLine/>:items.error?null:rows.length===0?<Empty>{view==='issues'&&!items.data?.build_id?'尚无成功构建。首次构建后，这里显示完整问题清单。':view==='tasks'?'当前筛选下没有探测任务；缺少精确目标的问题仍在规则问题中等待。':view==='records'?'当前筛选下没有执行记录。':'当前筛选下没有规则问题。'}</Empty>:<div className="table-scroll">
      {view==='issues'?<Table><Table.Thead><Table.Tr><Table.Th>问题对象</Table.Th><Table.Th>要核查什么</Table.Th><Table.Th>本轮规则处理</Table.Th><Table.Th>补充材料进度</Table.Th></Table.Tr></Table.Thead><Table.Tbody>{(rows as AuditIssue[]).map(r=><Table.Tr key={r.key}><Table.Td><Button variant="subtle" size="compact-sm" className="audit-link" onClick={()=>openIssue(r.key,shownBuild??null)}>{r.subject}</Button><Text size="xs" c="dimmed">{kindNames[r.kind]??r.kind}</Text>{r.targets?.length>0&&<Text size="xs" c="dimmed">候选 IP：{r.targets.slice(0,3).join('、')}</Text>}</Table.Td><Table.Td maw={330}><Text size="sm" lineClamp={3}>{r.reason}</Text></Table.Td><Table.Td maw={280}><Text size="sm">{r.rule_basis}</Text></Table.Td><Table.Td><State value={r.progress} view="issues"/>{r.job_count>0&&<Text size="xs" c="dimmed" mt={4}>{number(r.job_count)} 个关联任务</Text>}{r.progress==='returned'&&<Text size="xs" c="dimmed" mt={4}>不等于已确认地区或服务归属</Text>}</Table.Td></Table.Tr>)}</Table.Tbody></Table>:view==='tasks'?<Table><Table.Thead><Table.Tr><Table.Th>目标 / 方法</Table.Th><Table.Th>用途 / 视角</Table.Th><Table.Th>执行方</Table.Th><Table.Th>当前阶段</Table.Th><Table.Th>关联问题 / 目的</Table.Th><Table.Th/></Table.Tr></Table.Thead><Table.Tbody>{(rows as AuditTask[]).map(j=><Table.Tr key={j.id}><Table.Td><Button variant="subtle" size="compact-sm" className="audit-link" onClick={()=>openTask(j.id)}>{j.target}</Button><Text size="xs" c="dimmed">{kindNames[j.kind]??j.kind}</Text></Table.Td><Table.Td><Text size="sm">{j.purpose==='business'?'业务探测':'辅助目标发现'}</Text><Text size="xs" c="dimmed">{j.region==='any'?'按能力自动分配':regionName(j.region)}</Text></Table.Td><Table.Td maw={220}><Text size="sm">{observer(j.executor,j.node)}</Text></Table.Td><Table.Td><State view="tasks" value={j.state}/><Text size="xs" c="dimmed" mt={4}>{phaseNames[j.phase]??j.phase}</Text>{j.phase==='delayed'&&<Text size="xs" c="dimmed">可执行于 {time(j.not_before)}</Text>}</Table.Td><Table.Td>{issueLinks(j.cases??[])}{j.case_count>(j.cases?.length??0)&&<Text size="xs" c="dimmed">共 {number(j.case_count)} 个关联</Text>}</Table.Td><Table.Td><Button variant="subtle" size="compact-xs" onClick={()=>relatedRecords(caseKey||null,j.id)}>执行记录</Button></Table.Td></Table.Tr>)}</Table.Tbody></Table>:<Table><Table.Thead><Table.Tr><Table.Th>原任务 / 尝试</Table.Th><Table.Th>执行方 / 视角</Table.Th><Table.Th>回传情况</Table.Th><Table.Th>证据用途</Table.Th><Table.Th>观察 / 尝试时间</Table.Th><Table.Th/></Table.Tr></Table.Thead><Table.Tbody>{(rows as AuditRecord[]).map(r=><Table.Tr key={r.id}><Table.Td><Button variant="subtle" size="compact-sm" className="audit-link" onClick={()=>openTask(r.job_id)}>{r.target}</Button><Text size="xs" c="dimmed">{kindNames[r.kind]??r.kind} · {r.identity_known?`第 ${r.round_seq} 轮 / 尝试 ${r.attempt_seq}`:'原身份不完整，仅保留历史'}</Text></Table.Td><Table.Td><Text size="sm">{observer(r.executor,r.node)}</Text><Text size="xs" c="dimmed">要求视角：{r.region==='any'?'自动分配':regionName(r.region)}</Text></Table.Td><Table.Td><State view="records" value={r.record_kind}/>{r.outcome&&<Text size="xs" c="dimmed" mt={4}>{({ok:'执行返回成功',timeout:'目标超时',error:'执行失败',failed:'执行失败'} as Record<string,string>)[r.outcome]??r.outcome}</Text>}</Table.Td><Table.Td maw={320}><Text size="sm">{r.evidence_use}</Text>{r.record_kind==='returned'&&<Text size="xs" c="dimmed">{r.qualified?'符合该测量的复用资格':'未形成可复用资格'} · {freshness(r)}</Text>}</Table.Td><Table.Td>{r.observed?time(r.observed):<Text size="xs" c="dimmed">尚无观察回传</Text>}<Text size="xs" c="dimmed">尝试建立于 {time(r.created)}</Text></Table.Td><Table.Td><Button variant="subtle" size="compact-xs" onClick={()=>setRecord(r)}>详情</Button></Table.Td></Table.Tr>)}</Table.Tbody></Table>}
    </div>}
    <Group justify="flex-end" mt="lg"><Pagination value={page} total={pageCount} onChange={value=>go({page:String(value),...(view==='issues'&&shownBuild?{build_id:shownBuild}:{})})}/></Group>
    <Text className="audit-footnote" size="xs" c="dimmed">{view==='issues'?'问题按构建保留，本轮规则处理与探测进度分别展示。DNS 和 traceroute 不能直接判定目标地区或域名服务归属。':view==='tasks'?'同一共享任务只计一次。兼有业务用途的任务归入业务探测，全部用途保留在详情；辅助找目标的结束量不计为规则问题解决数。':'回执重传不增加执行记录，复用结果不增加新探测。Globalping 探针测试数在账户页独立计量，不与任务数或执行记录数相加。'}</Text>

    <Drawer opened={view==='issues'&&!!caseKey} onClose={()=>closeDetail('issues')} position="right" size="xl" title="规则问题">
      {items.isPending?<LoadingLine text="正在加载问题详情…"/>:issue?<Stack>
        <Title order={2}>{issue.subject}</Title><Text size="sm">{issue.reason}</Text>
        <section><Text size="xs" c="dimmed" mb={4}>本轮规则处理</Text><Text>{issue.rule_basis}</Text></section>
        <section><Text size="xs" c="dimmed" mb={4}>补充材料进度</Text><State value={issue.progress} view="issues"/><Text size="sm" mt="sm">{issue.targets?.length?`精确候选 IP：${issue.targets.join('、')}`:'尚无符合本轮策略的精确探测 IP；这与缺少执行节点不同。IPv6 不随机补地址。'}</Text></section>
        <IssueTargetDetails issue={issue} historical={items.data?.historical===true}/>
        <Group><Button variant="default" rightSection={<IconArrowRight size={14}/>} onClick={()=>relatedTasks(issue.key)}>查看关联任务</Button><Button variant="subtle" onClick={()=>relatedRecords(issue.key,null)}>查看执行记录</Button></Group>
        <Alert color="blue">测量回传只按实际方法和范围使用。端点响应不等于整个网段的位置结论，新结果由后续构建使用。</Alert>
        {issue.category==='measurable'&&issue.current&&issue.live_compatible!==false&&!items.data?.historical&&!['domain-policy','domain-observation'].includes(issue.kind)&&issue.payload?.measurement_required!==false&&<section><Title order={3} mb="sm">补充精确探测目标</Title><TextInput label="范围内的候选 IP，最多三个" description="填写已有依据的精确地址，不枚举网段。" value={candidate} onChange={e=>setCandidate(e.currentTarget.value)}/><ErrorBox error={saveTarget.error}/><Button variant="default" mt="sm" disabled={!candidate.trim()} loading={saveTarget.isPending} onClick={()=>saveTarget.mutate()}>保存探测目标</Button></section>}
        {issue.payload&&<Accordion><Accordion.Item value="source"><Accordion.Control>本轮问题资料</Accordion.Control><Accordion.Panel><JsonBlock value={issue.payload}/></Accordion.Panel></Accordion.Item></Accordion>}
      </Stack>:<><ErrorBox error={items.error}/><Empty>该构建清单中未找到此问题；历史执行记录仍会保留。</Empty><Button variant="default" onClick={()=>relatedRecords(caseKey,null)}>查看关联历史记录</Button></>}
    </Drawer>
    <Drawer opened={view==='tasks'&&!!jobId} onClose={()=>closeDetail('tasks')} position="right" size="xl" title="探测任务">
      {items.isPending?<LoadingLine text="正在加载任务详情…"/>:task?<Stack>
        <Title order={2}>{task.target}</Title><Text size="sm">{kindNames[task.kind]??task.kind} · {task.region==='any'?'按能力自动分配':regionName(task.region)}</Text>
        <Group><State value={task.state} view="tasks"/><Text size="sm">{phaseNames[task.phase]??task.phase}</Text></Group><Text size="sm">{task.reason}</Text>
        <Text size="sm">执行方：{observer(task.executor,task.node)}</Text><Text size="sm">本轮已用执行机会：{task.execution_count} / 3；更换执行方仍属同一个任务。</Text>
        <Text size="sm">用途：{task.purposes.map(p=>p==='business'?'业务探测':p==='discovery'?'辅助目标发现':p).join('、')}</Text>
        <Text size="xs" c="dimmed">创建于 {time(task.created)} · 可执行于 {time(task.not_before)}</Text>
        <Title order={3}>关联问题 / 目的</Title>{issueLinks(task.cases??[])}
        <Button variant="default" rightSection={<IconArrowRight size={14}/>} onClick={()=>relatedRecords(caseKey||null,task.id)}>查看该任务的执行记录</Button>
        {task.state==='unconfirmed'&&<Alert color="orange">提交或执行状态尚未核实。原意图与账目保留，不把它作为普通失败再次发送。</Alert>}
        <Text size="xs" c="dimmed" className="mono">任务 ID：{task.id}{task.remote_id?` · Globalping ID：${task.remote_id}`:''}</Text>
      </Stack>:<><ErrorBox error={items.error}/><Empty>当前筛选下没有此任务，可清除其他条件或查看执行历史。</Empty><Button variant="default" onClick={()=>relatedRecords(caseKey||null,jobId)}>查看执行记录</Button></>}
    </Drawer>
    <Drawer opened={view==='records'&&!!record} onClose={()=>setRecord(null)} position="right" size="xl" title="执行记录">
      {record&&<Stack><Title order={2}>{record.target}</Title><Group><State value={record.record_kind} view="records"/><Text size="sm">{observer(record.executor,record.node)}</Text></Group>
        <Text size="sm">{record.evidence_use}</Text><Text size="sm">{record.identity_known?`原任务第 ${record.round_seq} 轮、尝试 ${record.attempt_seq}`:'旧记录的原尝试身份不完整，保留历史，不纳入精确的已回传执行计数。'}</Text>
        <Text size="sm">观察于 {time(record.observed)}；收到回传于 {time(record.received)}</Text>
        {record.qualified!=null&&<Text size="sm">该测量的复用资格：{record.qualified?'符合':'未形成'}；{freshness(record)}{record.valid_until?`（有效至 ${time(record.valid_until)}）`:''}</Text>}
        {record.record_kind==='unconfirmed'&&<Alert color="orange">尚不能确认外部执行与实际消耗，原提交与预留仍保留；不盲目重发或退款。</Alert>}
        <Title order={3}>关联问题 / 目的</Title>{issueLinks(record.cases??[])}
        <Group><Button variant="default" onClick={()=>{setRecord(null);openTask(record.job_id);}}>查看原任务</Button>{!jobId&&<Button variant="subtle" onClick={()=>{setRecord(null);relatedRecords(caseKey||null,record.job_id);}}>查看该任务全部记录</Button>}</Group>
        {record.result!=null&&<Accordion><Accordion.Item value="raw"><Accordion.Control>原始回传</Accordion.Control><Accordion.Panel><JsonBlock value={record.result}/></Accordion.Panel></Accordion.Item></Accordion>}
        <Text size="xs" c="dimmed" className="mono">任务 ID：{record.job_id}</Text>
      </Stack>}
    </Drawer>
    <Modal opened={manualOpened} onClose={()=>setManualOpened(false)} title="临时探测"><form onSubmit={e=>{e.preventDefault();observe.mutate();}}><Stack><TextInput label="域名或 IP" placeholder="example.com / 1.1.1.1 / 2606:4700:4700::1111" value={target} onChange={e=>setTarget(e.currentTarget.value)}/><MultiSelect label="必要观测地区" data={regions} value={coverage} onChange={setCoverage}/><Checkbox label="要求新一轮观测" description="已有匹配且有效的结果可直接复用；强制新一轮仍不会绕过未决提交。" checked={refresh} onChange={e=>setRefresh(e.currentTarget.checked)}/><Text size="sm" c="dimmed">域名执行 DNS，IP 执行 traceroute。它们提供解析或端点信息，不能直接判定地区或服务归属。</Text><ErrorBox error={observe.error}/><Button type="submit" disabled={!target.trim()||coverage.length===0} loading={observe.isPending}>安排临时探测</Button></Stack></form></Modal>
  </div>;
}
