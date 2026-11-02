// Runtime proof: the copied controller serves exact assets while the source dist is absent.
import {mkdtemp,cp,rename,readFile,writeFile,access,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {randomUUID,createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const temporary=await mkdtemp(join(tmpdir(),'airroute-embedded-'));
const original=join(root,'web/console/dist');
const hidden=join(temporary,'source-assets');
const token=randomUUID()+randomUUID();
let child,hiddenAssets=false,logs='';
try {
  await cp(process.argv[2]?resolve(process.argv[2]):join(root,'target/release/rules-control'),join(temporary,'rules-control'));
  await cp(join(root,'config'),join(temporary,'config'),{recursive:true});
  // This runtime proof must never consume a real provider quota or publish.
  await writeFile(join(temporary,'config/globalping.toml'),'accounts=[]\n');
  await writeFile(join(temporary,'config/discovery.toml'),'enabled=false\n');
  await rename(original,hidden);hiddenAssets=true;
  const socket=createServer();await new Promise(r=>socket.listen(0,'127.0.0.1',r));
  const port=socket.address().port;await new Promise(r=>socket.close(r));
  child=spawn(join(temporary,'rules-control'),['serve','--offline','--bind',`127.0.0.1:${port}`,'--quic-bind','127.0.0.1:0','--interval-hours','0'],{cwd:temporary,env:{...process.env,AIRROUTE_ADMIN_TOKEN:token},stdio:['ignore','pipe','pipe']});
  child.stdout.on('data',b=>logs+=b);child.stderr.on('data',b=>logs+=b);
  const url=`http://127.0.0.1:${port}`;
  let healthy=false;
  for(let i=0;i<50;i++){
    if(child.exitCode!==null)throw new Error(`controller stopped: ${logs}`);
    try{healthy=(await fetch(url+'/healthz')).ok}catch{}
    if(healthy)break;await new Promise(r=>setTimeout(r,100));
  }
  assert(healthy,'controller did not start');
  await assert.rejects(access(original));
  const response=await fetch(url);assert.equal(response.status,200);assert(response.headers.has('content-security-policy'));
  const html=await response.text();const assets=[...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)].map(m=>m[1]);assert(assets.length>=2);
  const digest=b=>createHash('sha256').update(b).digest('hex');
  for(const asset of assets){const r=await fetch(url+asset);assert.equal(r.status,200);const bytes=Buffer.from(await r.arrayBuffer());assert.equal(digest(bytes),digest(await readFile(join(hidden,asset.slice(1)))));assert.equal((await fetch(url+asset,{headers:{'If-None-Match':r.headers.get('etag')}})).status,304);}
  assert.equal((await fetch(url+'/assets/missing.js')).status,404);
  assert.equal((await fetch(url+'/conflicts',{headers:{Accept:'text/html'}})).status,200);
  assert.equal((await fetch(url+'/api/missing',{headers:{Authorization:`Bearer ${token}`,Accept:'text/html'}})).status,404);
  assert.equal((await fetch(url+'/api/overview')).status,401);
  assert.equal((await fetch(url+'/api/overview',{headers:{Authorization:`Bearer ${token}`}})).status,200);
  // Empty, offline startup must initialize the existing schema before serving
  // the new read-only views; it must not rely on opening the account page first.
  for(const view of ['issues','tasks','records']){
    const r=await fetch(url+`/api/audit/${view}`,{headers:{Authorization:`Bearer ${token}`}});
    assert.equal(r.status,200,view);const value=await r.json();assert.equal(value.total,0);assert.deepEqual(value.items,[]);
  }
  console.log(JSON.stringify({standalone_binary:true,source_frontend_absent:true,assets_verified:assets.length,auth:true,etag:true,spa_and_404:true,audit_empty_offline_startup:true},null,2));
} finally {
  if(child&&child.exitCode===null){child.kill('SIGINT');await Promise.race([new Promise(r=>child.once('exit',r)),new Promise(r=>setTimeout(r,2000))]);if(child.exitCode===null)child.kill('SIGKILL');}
  if(hiddenAssets)await rename(hidden,original);
  await rm(temporary,{recursive:true,force:true});
}
