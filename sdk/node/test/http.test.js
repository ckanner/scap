/** Real loopback Fetch contracts; never used to fill unit coverage. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { gzipSync } from 'node:zlib';
import { Client, CatalogueClient, UnknownError, ClientError } from '../src/client.js';

const TOKEN = 'synthetic-http-only-bearer-credential';
const SCOPE = {deployment:'1',tenant:'2',database:'3',incarnation:'1',generation:'1'};
const SQL = [{sql:'SELECT 1',parameters:[]}];
const EMPTY = 'U0NBUFJFUzEAAAAA';

async function server(t, handle) {
  const app=createServer(handle);
  app.listen(0,'127.0.0.1');await once(app,'listening');
  t.after(async()=>{app.closeAllConnections();await new Promise((resolve,reject)=>app.close(error=>error?reject(error):resolve()));});
  return {endpoint:`http://127.0.0.1:${app.address().port}/v1`,app};
}
function client(endpoint, extra={}) {return new Client({endpoint,token:TOKEN,scope:SCOPE,principal:'7',...extra});}

test('actual Fetch sends a single authenticated typed POST and reads a chunked result',async(t)=>{
  const calls=[];
  const {endpoint}=await server(t,async(req,res)=>{
    const chunks=[];for await(const chunk of req)chunks.push(chunk);
    calls.push({method:req.method,path:req.url,headers:req.headers,body:JSON.parse(Buffer.concat(chunks))});
    res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'});
    res.write('{"ok":true,');res.end(`"value":{"result":"${EMPTY}"}}`);
  });
  assert.deepEqual(await client(endpoint).query([{sql:'SELECT ?1, ?2',parameters:[-(1n<<63n),-0]}]),{statements:[]});
  assert.equal(calls.length,1);assert.equal(calls[0].method,'POST');assert.equal(calls[0].path,'/v1');
  assert.equal(calls[0].headers.authorization,`Bearer ${TOKEN}`);assert.equal(calls[0].headers['x-scap-admission'],'data');
  assert.deepEqual(calls[0].body.statements[0].params,[{type:'integer',value:'-9223372036854775808'},{type:'real',bits:'8000000000000000'}]);
});

test('a real redirect never forwards a bearer credential or repeats SQL at its destination',async(t)=>{
  let destinationCalls=0,sourceCalls=0;
  const target=await server(t,(req,res)=>{destinationCalls++;res.end('{}');});
  const origin=await server(t,(req,res)=>{sourceCalls++;res.writeHead(307,{location:target.endpoint});res.end();});
  const c=client(origin.endpoint),request=c.prepare(SQL,{epoch:'1',id:'1'});
  await assert.rejects(c.execute(request),UnknownError);
  assert.equal(sourceCalls,1);assert.equal(destinationCalls,0);
});

test('a stalled real response ends at the original deadline with an unchanged unresolved request',async(t)=>{
  let calls=0;
  const {endpoint}=await server(t,(req,res)=>{calls++;res.writeHead(200,{'content-type':'application/json'});res.write('{');});
  const c=client(endpoint,{timeoutMs:80}),request=c.prepare(SQL,{epoch:'1',id:'9007199254740993'});
  await assert.rejects(c.execute(request),error=>error instanceof UnknownError&&error.cause.code==='DEADLINE'&&
    error.reference.request.id===request.request.id);
  assert.equal(calls,1);
});

test('the response byte limit applies after actual HTTP decompression',async(t)=>{
  const compressed=gzipSync(JSON.stringify({ok:true,value:{result:'A'.repeat(8192)}}));
  assert.ok(compressed.length<512);
  const {endpoint}=await server(t,(req,res)=>{
    res.writeHead(200,{'content-type':'application/json','content-encoding':'gzip','content-length':compressed.length});res.end(compressed);
  });
  await assert.rejects(client(endpoint,{maxResponseBytes:512}).query(SQL),error=>error instanceof ClientError&&error.code==='LIMIT');
});

test('actual catalogue Fetch retains a lost create intent and explicitly inspects its original identity',async(t)=>{
  const calls=[];
  const creation={creator:'7',operation:'18446744073709551615',name:'原名字😀',scope:SCOPE,expected_name_revision:null};
  const {endpoint}=await server(t,async(req,res)=>{
    const chunks=[];for await(const chunk of req)chunks.push(chunk);
    const body=JSON.parse(Buffer.concat(chunks));
    calls.push({path:req.url,headers:req.headers,body});
    if(body.operation==='prepare_create'){res.destroy();return;}
    res.writeHead(200,{'content-type':'application/json'});
    res.end(JSON.stringify({ok:true,value:{creation,phase:'reserved',binding_revision:'1',head_revision:null,
      initial_quota:{max_bytes:null},retention:{max_entries:4096,max_result_bytes:'268435456'}}}));
  });
  const c=new CatalogueClient({endpoint:endpoint+'/catalogue',token:TOKEN,deployment:'1',tenant:'2',principal:'7'});
  const action={operation:'prepare_create',name:creation.name,create_operation:creation.operation,
    expected_name_revision:null,options:{quota:{mode:'unlimited'}}};
  const intent=c.prepareIntent(action),saved=c.saveIntent(intent);
  await assert.rejects(c.submit(intent),error=>error instanceof UnknownError&&error.reference.intent===intent);
  assert.equal(calls.length,1);
  assert.deepEqual(c.restoreIntent(saved),intent);
  const result=await c.inspectCreateOperation(creation.operation);
  assert.equal(result.phase,'reserved');assert.equal(result.head_revision,null);
  assert.equal(calls.length,2);assert.equal(calls[0].path,'/v1/catalogue');
  for(const call of calls){assert.equal(call.headers['x-scap-admission'],'catalogue');assert.equal(call.headers.authorization,`Bearer ${TOKEN}`);}
  assert.deepEqual(calls[0].body,{version:1,...action});
  assert.deepEqual(calls[1].body,{version:1,operation:'inspect_create_operation',create_operation:creation.operation});
});
