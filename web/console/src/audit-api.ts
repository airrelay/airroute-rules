import type { Json } from './api';

export type AuditView = 'issues' | 'tasks' | 'records';
export interface AuditCaseLink { key:string; subject:string; kind:string; current:boolean }
export interface AuditIssue {
  key:string; fingerprint:string; kind:string; subject:string; reason:string;
  category:string; rule_basis:string; progress:string; targets:string[];
  job_count:number; current:boolean; live_compatible?:boolean; payload?:Json;
  target_evidence?:Json; target_evidence_is_live?:boolean;
}
export interface AuditTask {
  id:string; kind:string; target:string; region:string; purpose:string; purposes:string[];
  state:string; phase:string; reason:string; executor:string; node:string|null;
  created:number; not_before:number; round_seq:number; execution_count:number; attempt_seq:number;
  case_count:number; cases:AuditCaseLink[]; remote_id?:string|null;
}
export interface AuditRecord {
  id:string; job_id:string; target:string; kind:string; region:string; node:string|null;
  executor:string; attempt_seq:number|null; round_seq:number|null; created:number;
  observed:number|null; received:number|null; outcome:string|null; qualified:boolean|null;
  fresh:boolean|null; valid_until:number|null; accepted:boolean|null; identity_known:boolean;
  record_kind:string; evidence_use:string; qualification?:unknown; result?:unknown;
  cases:AuditCaseLink[];
}
export interface AuditResponse<T> {
  items?:T[]; total?:number; states?:Record<string,number>; categories?:Record<string,number>;
  full_total?:number; build_id?:string|null; current_build_id?:string|null;
  release_hash?:string|null; built_at?:number|null; observation_cutoff?:number|null;
  historical?:boolean; scope?:{unit?:string; at?:number; build_id?:string|null; [key:string]:unknown};
}
export const auditPageSize = 30;
const views:AuditView[]=['issues','tasks','records'];
export function auditView(p:URLSearchParams):AuditView {
  const v=p.get('view');return views.includes(v as AuditView)?v as AuditView:'issues';
}
export function auditPage(p:URLSearchParams):number {
  const n=Number(p.get('page')??1);return Number.isSafeInteger(n)&&n>0?n:1;
}
export function auditParams(hash:string):URLSearchParams {
  return new URLSearchParams(hash.replace(/^#/,'').split('?').slice(1).join('?'));
}
/** Keep existing bookmarks usable, including their selected case and old filters. */
export function normalizeAuditHash(hash:string):string {
  const raw=hash.replace(/^#/,''),[page]=raw.split('?');
  if(!['tasks','conflicts','audit'].includes(page))return hash;
  const p=auditParams(hash);
  if(page!=='audit')p.set('view',page==='tasks'?'tasks':'issues');
  if(!p.get('case_key')&&p.get('key'))p.set('case_key',p.get('key')!);
  p.delete('key');
  const filter=p.get('filter');
  if(filter){
    const value=filter.replace(/^(source|state|kind|status):/,'');
    if(page==='tasks'){
      if(['build','manual'].includes(value))p.set('purpose','business');
      else if(value==='discovery')p.set('purpose','discovery');
      else if(['running','leased'].includes(value))p.set('state','processing');
      else if(['queued','scheduled','pending'].includes(value))p.set('state','queued');
      else if(value==='complete'){p.set('range','ended');p.set('state','ended');}
      else if(value==='obsolete'){p.set('range','all');p.set('state','obsolete');}
      else if(['unknown','failed'].includes(value)){p.set('range','current');p.delete('state');}
    }else if(page==='conflicts'){
      if(['geolocation','domain-policy','anycast-review'].includes(value))p.set('category','sources');
      else if(value==='coverage-gap')p.set('category','gaps');
      else if(value==='anycast-validation')p.set('category','measurable');
      else p.set('category','all');
    }
    // Preserve the original selector for compatibility handling and a visible notice.
    p.set('legacy_filter',filter);p.delete('filter');
  }
  if(auditView(p)==='issues')p.delete('job_id');
  return '#audit'+(p.size?'?'+p.toString():'');
}
/** Store per-view search/state/page so following relationships does not destroy a list. */
export function auditHref(current:URLSearchParams,patch:Record<string,string|null>):string {
  const from=auditView(current),to=patch.view as AuditView|undefined;
  const saved=to&&to!==from?restoreList(current,to):null;
  const p=saved??new URLSearchParams(current);
  if(to&&to!==from){
    const origin=listParams(current,from)??current;
    for(const key of ['q','state','page']){
      const old=origin.get(key);if(old)p.set(`${from}_${key}`,old);else p.delete(`${from}_${key}`);
      if(!saved){const next=current.get(`${to}_${key}`);if(next)p.set(key,next);else p.delete(key);}
    }
  }
  for(const [key,value] of Object.entries(patch)){
    if(value==null||value==='')p.delete(key);else p.set(key,value);
  }
  // An explicit relationship keeps its source build provenance even when the
  // target tab has an older saved list. The build is a return/context label,
  // not a claim that its retained attempts all ran during that build.
  if((Object.hasOwn(patch,'case_key')||Object.hasOwn(patch,'job_id'))&&!Object.hasOwn(patch,'build_id')){
    const build=current.get('build_id');
    if(p.get('case_key')&&build)p.set('build_id',build);else p.delete('build_id');
  }
  // A job is not an accepted issue-list filter. Never leave a misleading chip.
  if(auditView(p)==='issues')p.delete('job_id');
  return '#audit'+(p.size?'?'+p.toString():'');
}
function listParams(current:URLSearchParams,view:AuditView):URLSearchParams|null {
  const raw=current.get(`${view}_list`);
  if(!raw)return null;
  const p=new URLSearchParams(raw);return auditView(p)===view?p:null;
}
function restoreList(current:URLSearchParams,view:AuditView):URLSearchParams|null {
  const p=listParams(current,view);if(!p)return null;
  for(const [key,value] of current){
    if(key!==`${view}_list`&&/^(issues|tasks|records)_(q|state|page|list)$/.test(key))p.set(key,value);
  }
  return p;
}
/** A drawer has one small return snapshot; snapshots never contain other snapshots. */
export function auditDetailHref(current:URLSearchParams,view:'issues'|'tasks',id:string,buildId?:string|null):string {
  const p=auditParams(auditHref(current,{view})),key=`${view}_list`;
  if(!p.has(key)){
    const saved=new URLSearchParams(p);for(const name of ['issues_list','tasks_list','records_list'])saved.delete(name);
    p.set(key,saved.toString());
  }
  return auditHref(p,view==='issues'
    ?{case_key:id,job_id:null,category:'all',q:null,state:null,page:'1',...(buildId!==undefined?{build_id:buildId}:{})}
    :{job_id:id,case_key:current.get('case_key'),build_id:current.get('build_id'),purpose:'all',range:'all',q:null,state:null,page:'1'});
}
export function auditCloseDetailHref(current:URLSearchParams,view:'issues'|'tasks'):string {
  const saved=restoreList(current,view);
  return saved?auditHref(saved,{view}):auditHref(current,view==='issues'?{case_key:null,page:'1'}:{job_id:null,page:'1'});
}
export function auditQuery(view:AuditView,p:URLSearchParams,part:'items'|'summary',buildId?:string|null):string {
  const query=new URLSearchParams({part});
  const fields=view==='issues'
    ?['category','state','case_key','q','build_id']
    :view==='tasks'?['purpose','range','state','case_key','job_id','q']
      :['purpose','state','case_key','job_id','q','after','before'];
  for(const field of fields){const value=p.get(field);if(value)query.set(field,value);}
  if(view==='issues'&&buildId)query.set('build_id',buildId);
  if(part==='items'){query.set('offset',String((auditPage(p)-1)*auditPageSize));query.set('limit',String(auditPageSize));}
  return `audit/${view}?${query.toString()}`;
}
