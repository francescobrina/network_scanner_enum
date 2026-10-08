import test from 'node:test';
import assert from 'node:assert/strict';
import {compare, normalizeReport, summary, safeFilename} from '../logic.mjs';
const report = (state='closed', completed=true) => ({
 target:'127.0.0.1', resolved_ip:'127.0.0.1', started_at:'2026-10-08T09:00:00Z',
 duration_s:.1, completed, results:[{port:22,state,service:'SSH'},{port:443,state:'open',service:'HTTPS',tls:{verified:true}}]
});
test('normalize sorts and strips untrusted fields', () => {
 const n=normalizeReport({...report(),secret:'oops'});
 assert.equal(n.results[0].port,22);assert.ok(!Object.hasOwn(n,'secret'));
});
test('new exposure change is detected', () => {
 const n=compare(report('closed'),report('open'));
 assert.equal(n.findings.filter(f=>f.kind==='new-exposure').length,1);
 assert.equal(n.open_count,2);
});
test('unscanned is not closed',()=>{
 const b=report('open');const now=report('closed');now.results=now.results.filter(x=>x.port!==22);
 const result=compare(b,now);
 assert.deepEqual(result.unscanned,[22]); assert.equal(result.changes.length,0);
});
test('reject cross target', () => {
 assert.throws(()=>compare(report(),{...report(),target:'other'}),/Targets differ/);
});
test('invalid state and duplicate ports rejected',()=>{
 assert.throws(()=>normalizeReport({...report(),results:[{port:22,state:'open'},{port:22,state:'open'}]}),/duplicate/);
 assert.throws(()=>normalizeReport({...report(),results:[{port:22,state:'vulnerable'}]}),/state/);
});
test('DNS drift and incomplete scans warn',()=>{
 const a=report(),b={...report('open',false),resolved_ip:'127.0.0.2'};
 const r=compare(a,b); assert.equal(r.warnings.length,2);
});
test('single scan no inferred exposure',()=>{
 const s=summary(report('open'));assert.equal(s.findings.length,0);
 assert.ok(s.warnings.some(w=>w.includes('baseline')));
});
test('file names are sanitized',()=>{
 assert.equal(safeFilename('test.host/../../evil'),'test_host_______evil');
});
