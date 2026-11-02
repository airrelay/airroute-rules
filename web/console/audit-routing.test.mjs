import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import test from 'node:test';
import ts from 'typescript';

// Execute the actual pure TS owner, without a browser or a second route model.
const source=await readFile(new URL('./src/audit-api.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
const {normalizeAuditHash,auditHref,auditParams,auditQuery,auditView,auditPage,auditDetailHref,auditCloseDetailHref}=await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

test('old entry points retain case identity and make filter translation visible',()=>{
  const p=auditParams(normalizeAuditHash('#tasks?key=case%2Fone&filter=source%3Adiscovery'));
  assert.equal(p.get('view'),'tasks');assert.equal(p.get('case_key'),'case/one');
  assert.equal(p.get('purpose'),'discovery');assert.equal(p.get('legacy_filter'),'source:discovery');
  const issue=auditParams(normalizeAuditHash('#conflicts?filter=kind%3Ageolocation'));
  assert.equal(issue.get('view'),'issues');assert.equal(issue.get('category'),'sources');
  assert.equal(normalizeAuditHash('#probes'),'#probes');
  const retired=auditParams(normalizeAuditHash('#tasks?filter=state%3Aobsolete'));
  assert.equal(retired.get('range'),'all');assert.equal(retired.get('state'),'obsolete');
  const failed=auditParams(normalizeAuditHash('#tasks?filter=state%3Afailed'));
  assert.equal(failed.get('range'),'current');assert.equal(failed.get('state'),null);
  assert.equal(failed.get('legacy_filter'),'state:failed');
});

test('switching views restores each list search, state and page',()=>{
  const initial=new URLSearchParams({view:'tasks',q:'exact.example',state:'queued',page:'3',records_q:'old-query',records_state:'returned',records_page:'2'});
  const records=auditParams(auditHref(initial,{view:'records'}));
  assert.equal(records.get('q'),'old-query');assert.equal(records.get('state'),'returned');assert.equal(records.get('page'),'2');
  const tasks=auditParams(auditHref(records,{view:'tasks'}));
  assert.equal(tasks.get('q'),'exact.example');assert.equal(tasks.get('state'),'queued');assert.equal(tasks.get('page'),'3');
});

test('following a relationship applies its scope and does not inherit incompatible list state',()=>{
  const initial=new URLSearchParams({view:'issues',category:'measurable',q:'93.93.51',state:'awaiting-target',page:'4'});
  const linked=auditParams(auditHref(initial,{view:'tasks',case_key:'case:exact',q:null,state:null,page:null}));
  assert.equal(linked.get('case_key'),'case:exact');assert.equal(linked.get('q'),null);assert.equal(linked.get('state'),null);
  const returned=auditParams(auditHref(linked,{view:'issues',case_key:null}));
  assert.equal(returned.get('q'),'93.93.51');assert.equal(returned.get('state'),'awaiting-target');assert.equal(returned.get('page'),'4');
});

test('items and summary send the identical semantic filter scope',()=>{
  for(const view of ['issues','tasks','records']){
    const p=new URLSearchParams({view,case_key:'range/one',job_id:'task two',q:'%_search',state:'some-state',purpose:'business',range:'all',category:'sources',build_id:'old-build',after:'100',before:'200',page:'3'});
    const a=new URLSearchParams(auditQuery(view,p,'items').split('?')[1]);
    const b=new URLSearchParams(auditQuery(view,p,'summary').split('?')[1]);
    assert.equal(a.get('offset'),'60');assert.equal(a.get('limit'),'30');
    a.delete('offset');a.delete('limit');a.delete('part');b.delete('part');
    assert.deepEqual([...a],[...b]);
    assert.equal(a.get('case_key'),'range/one');
  }
});

test('a pinned build is sent to both issue requests and invalid navigation has safe defaults',()=>{
  for(const part of ['items','summary'])assert.equal(new URLSearchParams(auditQuery('issues',new URLSearchParams(),part,'fixed-build').split('?')[1]).get('build_id'),'fixed-build');
  assert.equal(auditView(new URLSearchParams({view:'unknown'})),'issues');
  for(const page of ['0','-1','NaN','Infinity','1.5'])assert.equal(auditPage(new URLSearchParams({page})),1);
});

test('relationship jumps retain the originating build despite another tab return snapshot',()=>{
  const p=new URLSearchParams({view:'issues',case_key:'old-case',build_id:'old-build',tasks_list:'view=tasks&case_key=other-case&build_id=other-build'});
  const task=auditParams(auditHref(p,{view:'tasks',case_key:'old-case',job_id:null,page:'1'}));
  assert.equal(task.get('build_id'),'old-build');assert.equal(task.get('case_key'),'old-case');
  const record=new URLSearchParams({view:'records',case_key:'old-case',build_id:'old-build',tasks_list:'view=tasks&case_key=other-case&build_id=other-build'});
  const detail=auditParams(auditDetailHref(record,'tasks','old-task'));
  assert.equal(detail.get('build_id'),'old-build');assert.equal(detail.get('case_key'),'old-case');
  assert.equal(detail.get('job_id'),'old-task');
});

test('switching from a selected task to issues removes the unsupported job filter',()=>{
  const issue=auditParams(auditHref(new URLSearchParams({view:'tasks',job_id:'job:one',case_key:'case:one'}),{view:'issues'}));
  assert.equal(issue.get('job_id'),null);
  assert.equal(issue.get('case_key'),'case:one');
  assert.equal(new URLSearchParams(auditQuery('issues',issue,'items').split('?')[1]).has('job_id'),false);
  assert.equal(auditParams(normalizeAuditHash('#audit?view=issues&job_id=ignored')).has('job_id'),false);
});

test('closing issue and task details restores the exact prior list filters and page',()=>{
  for(const view of ['issues','tasks']){
    const initial=new URLSearchParams({view,page:'3',q:'chosen-target',state:view==='issues'?'awaiting-target':'queued',category:'measurable',purpose:'discovery',range:'current',build_id:'original-build',case_key:view==='tasks'?'related-case':''});
    const detail=auditParams(auditDetailHref(initial,view,'selected-id','pinned-detail-build'));
    assert.equal(detail.get('page'),'1');
    assert.equal(detail.get(view==='issues'?'case_key':'job_id'),'selected-id');
    const restored=auditParams(auditCloseDetailHref(detail,view));
    assert.deepEqual([...restored],[...initial]);
    assert.equal(restored.get('page'),'3');
    const records=auditParams(auditHref(detail,{view:'records',job_id:'selected-job',case_key:'selected-case',q:null,state:null,page:'1'}));
    const back=auditParams(auditHref(records,{view}));
    assert.equal(back.get('page'),'3');assert.equal(back.get('q'),'chosen-target');
    assert.equal(back.get('state'),initial.get('state'));
    assert.equal(back.get(view==='issues'?'case_key':'job_id'),initial.get(view==='issues'?'case_key':'job_id'));
  }
});
