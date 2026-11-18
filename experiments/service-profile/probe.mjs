/** Diagnostic workload only; never substitutes for object-load's frozen evidence contract. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const [configuration, output] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configuration, 'utf8'));
// Optional out-of-band handshake for the historical 2x2 diagnostic. It runs
// outside each timed phase and adds no product request or object operation.
const observerInput = config.observer_pipe ? createInterface({input:process.stdin}) : null;
const observer = async (phase, edge) => {
  if (!observerInput) return null;
  const reply = new Promise(resolve => observerInput.once('line', line => resolve(JSON.parse(line))));
  process.stdout.write(JSON.stringify({diagnostic_observer:{phase,edge}})+'\n');
  return reply;
};
const { Client } = await import(pathToFileURL(config.source_root + '/sdk/node/src/client.js'));
const sha = value => createHash('sha256').update(value).digest('hex');
const specs = [['seq','7','101'], ['same','7','102'], ['m0','7','201'], ['m1','7','202'], ['m2','8','301'], ['m3','8','302']];
const observations = [], calls = [], expected = new Map(), originals = [];
const clients = Object.fromEntries(specs.map(([name,tenant,database]) => [name, new Client({
  endpoint: config.endpoint + '/v1', token: config.tokens[tenant],
  scope: { deployment: '1',tenant,database,incarnation:'1',generation:'1' },
  principal: tenant === '7' ? '11' : '22', allowInsecureHttp: true,
  timeoutMs:65000,recoveryTimeoutMs:70000,
  fetch: async (url, options) => {
    const body=Buffer.from(options.body);
    observations.push({request_sha256:sha(body),bytes:body.length});
    return globalThis.fetch(url,options);
  },
})]));
const stmt=(sql,parameters=[])=>({sql,parameters});
const payload=id=>Buffer.from(Array.from({length:4096},(_,i)=>(i*37+id*19+(i>>>5))%256));
const snapshot=async()=>{
  const response=await fetch(config.endpoint+'/__profile');
  assert.equal(response.status,200);
  return response.json();
};
const phases=[];
try {
  for (const [name,,database] of specs) {
    const c=clients[name]; expected.set(name,[]);
    await c.create({nonce:String(Number(database)*10+1)});
    await c.activate({expectedRevision:'1',nonce:String(Number(database)*10+2)});
    await c.execute(c.prepare([stmt('CREATE TABLE loads(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)')],{epoch:'1',id:'1'}));
  }
  for(const [phase,count,concurrency] of [['write_seq',16,1],['write_multi',64,4],['write_same',32,4],['read_multi',32,4]]) {
    const work=Array.from({length:count},(_,index)=>{
      const name=phase.endsWith('multi')?'m'+index%4:phase==='write_seq'?'seq':'same';
      const id=phase.endsWith('multi')?Math.floor(index/4):index;
      const request=phase.startsWith('write')?clients[name].prepare([stmt('INSERT INTO loads(id,payload) VALUES(?,?) RETURNING id,payload,random() AS witness',[BigInt(id),payload(id)])],{epoch:'1',id:String(id+2)}):null;
      return {name,id,request};
    });
    const observer_before=await observer(phase,'before');
    const before=await snapshot(),start=process.hrtime.bigint();
    await Promise.all(Array.from({length:concurrency},async(_,lane)=>{
      for(let index=lane;index<count;index+=concurrency) {
        const {name,id,request}=work[index],begin=process.hrtime.bigint();
        const call={phase,index,name}; calls.push(call);
        try {
          if(request) {
            const value=await clients[name].execute(request);
            assert.equal(value.state,'committed');
            const [row,bytes]=value.result.statements[0].rows[0];
            assert.equal(row,BigInt(id)); assert.deepEqual(Buffer.from(bytes),payload(id));
            expected.get(name).push(id);
            originals.push({name,serialized:clients[name].save(request),raw:Buffer.from(value.rawResult).toString('base64')});
          } else {
            const value=await clients[name].query([stmt('SELECT count(*) FROM loads')]);
            assert.equal(value.statements[0].rows[0][0],16n);
          }
          call.ok=true;
        } catch(error) {call.ok=false;call.error={name:error.name,code:error.code??null,message:error.message};}
        call.elapsed_ns=Number(process.hrtime.bigint()-begin);
      }
    }));
    const elapsed_ns=Number(process.hrtime.bigint()-start),after=await snapshot();
    const observer_after=await observer(phase,'after');
    phases.push({phase,count,concurrency,elapsed_ns,before,after,observer_before,observer_after});
    assert.equal(calls.filter(c=>c.phase===phase&&!c.ok).length,0);
  }
  for(const original of originals) {
    const c=clients[original.name],reply=await c.lookup(c.restore(original.serialized));
    assert.equal(reply.state,'committed');
    assert.equal(Buffer.from(reply.rawResult).toString('base64'),original.raw);
  }
  for(const [name,ids] of expected) {
    const rows=(await clients[name].query([stmt('SELECT id,payload FROM loads ORDER BY id')])).statements[0].rows;
    ids.sort((a,b)=>a-b); assert.equal(rows.length,ids.length);
    rows.forEach(([id,bytes],i)=>{ assert.equal(id,BigInt(ids[i])); assert.deepEqual(Buffer.from(bytes),payload(ids[i])); });
  }
  console.log(JSON.stringify({ok:true,phases:phases.length,measured_calls:calls.length,original_lookups:originals.length,final_databases:expected.size}));
} finally {
  observerInput?.close();
  writeFileSync(output,JSON.stringify({schema:1,diagnostic_only:true,phases,calls,observations,originals},null,2));
}
