import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DiscoveryClient, ClientError, RemoteError } from '../src/client.js';
import * as wire from '../src/discovery_wire.js';

const U64='18446744073709551615';
const CONTEXT={deployment:'9007199254740993',tenant:'9007199254740995',principal:'17'};
const OPTIONS={endpoint:'http://127.0.0.1:8123/v1/discovery',token:'synthetic-discovery-unit-only-credential',...CONTEXT};
const SCOPE={deployment:CONTEXT.deployment,tenant:CONTEXT.tenant,database:U64,incarnation:'1',generation:'1'};
const CREATION={creator:'17',operation:U64,name:'目录😀',scope:SCOPE,expected_name_revision:null};
const clone=value=>JSON.parse(JSON.stringify(value));
const invalid=fn=>assert.throws(fn,e=>e instanceof ClientError&&e.code==='INVALID');
const response=value=>new Response(JSON.stringify({ok:true,value}),{headers:{'content-type':'application/json'}});
const names=()=>({names:[{creation:clone(CREATION),binding_revision:U64,head_revision:U64}],cursor:null,traversal_exhausted:true,stopped:null});
const record=()=>({key:`scap-object/v1/${CONTEXT.deployment}/${CONTEXT.tenant}/${U64}/head`,kind:'head',state:'ready',
  creation:clone(CREATION),scope:clone(SCOPE),control:null,binding_revision:U64,head_revision:U64});
const control=()=>({kind:'abort',principal:'17',operation:U64,expected_name_revision:U64,expected_head_revision:null,nonce:U64});
const inventory=()=>({records:[record()],cursor:null,stopped:null,
  completion:{traversal_exhausted:true,preexisting_slots_covered:true,metadata_classified:U64,data_recovery:'not_run',recovery_complete:false},
  usage:{list_pages:4,candidates:128,exact_gets:512,list_bytes:4194304,metadata_bytes:16777216}});

test('discovery issues one read attempt per page with opaque explicit continuation and lossless identities',async()=>{
  let calls=[];const c=new DiscoveryClient({...OPTIONS,fetch:(_url,init)=>{
    const body=JSON.parse(init.body);calls.push({body,init});
    return response(body.operation==='list_names'?names():inventory());
  }});
  assert.deepEqual([c.deployment,c.tenant,c.principal],Object.values(CONTEXT));
  assert.equal((await c.listNames()).names[0].creation.scope.database,U64);
  assert.equal((await c.deploymentInventory()).completion.recovery_complete,false);
  await c.listNames('opaque_cursor-1',{timeoutMs:1000});
  await c.deploymentInventory('another_cursor-2',{timeoutMs:1000});
  assert.equal(calls.length,4);assert.equal(calls[0].body.cursor,null);assert.equal(calls[2].body.cursor,'opaque_cursor-1');
  for(const {body,init} of calls){assert.deepEqual(Object.keys(body).sort(),['cursor','operation','version']);assert.equal(init.headers['x-scap-admission'],'discovery');assert.equal(init.redirect,'error');}
  const partial=names();partial.cursor='continued';partial.traversal_exhausted=false;partial.stopped='LIMIT';
  let count=0;const bounded=new DiscoveryClient({...OPTIONS,fetch:()=>{count++;return response(partial);}});
  assert.equal((await bounded.listNames()).stopped,'LIMIT');assert.equal(count,1);
  const frozen=value=>{assert.equal(Object.isFrozen(value),true);for(const child of Object.values(value)){if(child!==null&&typeof child==='object')frozen(child);}};
  frozen(wire.names(names(),CONTEXT));frozen(wire.inventory(inventory(),CONTEXT));
});

test('discovery constructor budgets and cursor syntax reject before any transport',()=>{
  new DiscoveryClient({...OPTIONS,maxRequestBytes:100,maxResponseBytes:200});
  for(const [key,max] of [['maxRequestBytes',65536],['maxResponseBytes',1048576]])for(const value of [0,-1,1.5,'20',max+1])invalid(()=>new DiscoveryClient({...OPTIONS,[key]:value}));
  invalid(()=>new DiscoveryClient({...OPTIONS,scope:SCOPE}));
  assert.equal(wire.cursor(null),null);assert.equal(wire.cursor('abc_DEF-09'),'abc_DEF-09');
  for(const token of [undefined,1,{},'', 'x'.repeat(16385),'abc=','a b','目录'])invalid(()=>wire.cursor(token));
  const c=new DiscoveryClient({...OPTIONS,fetch:()=>assert.fail('invalid input reached transport')});
  invalid(()=>c.listNames(1));invalid(()=>c.deploymentInventory(''));
});

test('metadata pages cannot claim health or hide incomplete traversal and retain cross-tenant inventory only',()=>{
  const n=names();n.cursor='cursor';n.traversal_exhausted=false;n.stopped=null;
  assert.equal(wire.names(n,CONTEXT).cursor,'cursor');
  for(const stopped of ['INVALID','DENIED','LIMIT','CONFLICT','UNKNOWN','CORRUPT']){n.stopped=stopped;assert.equal(wire.names(n,CONTEXT).stopped,stopped);}
  const i=inventory();i.records[0].creation.scope.tenant='42';i.records[0].scope.tenant='42';
  assert.equal(wire.inventory(i,CONTEXT).records[0].scope.tenant,'42');
  invalid(()=>wire.names({...names(),names:[{...names().names[0],creation:i.records[0].creation}]},CONTEXT));
  for(const scope of [null,clone(SCOPE)])for(const creation of [null,clone(CREATION)]) {
    const v=inventory();Object.assign(v.records[0],{scope,creation,binding_revision:null,head_revision:null});
    assert.equal(wire.inventory(v,CONTEXT).records[0].binding_revision,null);
  }
  for(const kind of ['name','create','control','abort_proof','head','orphan_prefix'])for(const state of ['descriptor_only','reserved','provisioning','bound','ready','maintenance','aborting','aborted','deleting','deleted','name_conflict','identity_conflict','control_admitted','orphan']){
    const v=inventory();Object.assign(v.records[0],{kind,state,control:kind==='control'?control():null});assert.equal(wire.inventory(v,CONTEXT).records[0].state,state);
  }
  const empty=inventory();empty.records=[];empty.completion.metadata_classified='0';for(const key of Object.keys(empty.usage))empty.usage[key]=0;
  assert.equal(wire.inventory(empty,CONTEXT).completion.metadata_classified,'0');
});

test('inventory preserves original control conditions without granting impersonation or rewriting intent',()=>{
  const base=inventory();base.records[0].kind='control';base.records[0].control=control();
  assert.deepEqual(wire.inventory(base,CONTEXT).records[0].control,control());
  const deleted=clone(base);deleted.records[0].control.kind='delete';deleted.records[0].control.expected_head_revision=U64;
  assert.equal(wire.inventory(deleted,CONTEXT).records[0].control.expected_head_revision,U64);
  for(const modify of [v=>{v.records[0].control=null;},v=>{v.records[0].kind='head';},v=>{v.records[0].creation=null;},
    v=>{v.records[0].control.kind='unknown';},v=>{v.records[0].control.expected_head_revision=U64;},
    v=>{v.records[0].control.kind='delete';},v=>{v.records[0].control.nonce=1;},v=>{delete v.records[0].control.operation;}]){
    const v=clone(base);modify(v);invalid(()=>wire.inventory(v,CONTEXT));
  }
});

test('discovery decoders reject malformed metadata counts authorities classifications and proof claims',()=>{
  const badNames=[v=>{v.names={};},v=>{v.names=Array(129).fill(names().names[0]);},v=>{v.cursor='cursor';},
    v=>{v.traversal_exhausted='true';},v=>{v.stopped='UNKNOWN';},v=>{v.stopped='invented';},v=>{v.names[0].head_revision=1;},v=>{v.usage={};}];
  for(const change of badNames){const v=names();change(v);invalid(()=>wire.names(v,CONTEXT));}
  const badInventory=[v=>{v.completion.recovery_complete=true;},v=>{v.completion.data_recovery='verified';},v=>{v.completion.preexisting_slots_covered=false;},
    v=>{v.completion.metadata_classified='01';},v=>{v.records={};},v=>{v.records=Array(129).fill(record());},v=>{v.records[0].kind='invented';},v=>{v.records[0].state='invented';},
    v=>{v.records[0].scope.deployment='2';},v=>{v.records[0].creation.scope.deployment='2';},v=>{v.records[0].scope.database='2';},v=>{v.records[0].binding_revision=1;}];
  for(const key of [1,'bad',`scap-object/v1/${CONTEXT.deployment}/\n`,`scap-object/v1/${CONTEXT.deployment}/\ud800`,'x'.repeat(1025)])badInventory.push(v=>{v.records[0].key=key;});
  for(const [key,max] of Object.entries(inventory().usage))for(const value of [-1,1.5,'1',max+1])badInventory.push(v=>{v.usage[key]=value;});
  for(const change of badInventory){const v=inventory();change(v);invalid(()=>wire.inventory(v,CONTEXT));}
  const partial=inventory();partial.cursor='partial';partial.completion.traversal_exhausted=false;partial.completion.preexisting_slots_covered=false;partial.stopped='UNKNOWN';
  assert.equal(wire.inventory(partial,CONTEXT).stopped,'UNKNOWN');
});

test('read failures stay explicit and never restart a cursor or materialize an empty success',async()=>{
  let count=0;const bad=new DiscoveryClient({...OPTIONS,fetch:()=>{count++;throw new Error('fixture wire loss');}});
  for(const method of ['listNames','deploymentInventory'])await assert.rejects(bad[method](),e=>e instanceof ClientError&&e.code==='TRANSPORT'&&e.name==='ClientError');
  assert.equal(count,2);
  for(const [code,status] of [['CURSOR_INVALID',400],['DENIED',403],['UNAVAILABLE',503]]) {
    const c=new DiscoveryClient({...OPTIONS,fetch:()=>new Response(JSON.stringify({ok:false,error:{code,message:'fixture'}}),{status,headers:{'content-type':'application/json'}})});
    await assert.rejects(c.listNames('opaque'),e=>e instanceof RemoteError&&e.code===code);
  }
  const budget=new DiscoveryClient({...OPTIONS,maxResponseBytes:64,fetch:()=>response(names())});
  await assert.rejects(budget.listNames(),e=>e instanceof ClientError&&e.code==='LIMIT');
});
