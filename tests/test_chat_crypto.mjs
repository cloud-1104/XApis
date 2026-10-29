import test from 'node:test';
import assert from 'node:assert/strict';
import {sendPayload,keyPayload,messageView,decryptForDisplay,newConversationKeys} from '../console/static/chat-protocol.mjs';
import {plaintextPayload} from '../console/static/chat-plaintext.mjs';
import {createChat} from '../frontend/node_modules/@xdevplatform/chat-xdk/index.js';

// No account, PIN, or network is used in these encryption round trips.
globalThis.fetch = async () => { throw new Error('Offline test: network disabled'); };
const builtin = process.getBuiltinModule;
process.getBuiltinModule = name => ['http','https','node:http','node:https'].includes(name) ? {get(){throw new Error('Offline test: network disabled');}} : builtin(name);
async function fixture() {
  const chat = await createChat({getAuthToken:async()=>'',juiceboxModule:{Configuration:class{},Client:class{}}});
  const registered = chat.generateKeypairs();
  chat.setIdentity({userId:'123',signingKeyVersion:'1'});
  const keys = chat.getPublicKeys();
  const signingKeys = [{userId:'123',publicKeyVersion:'1',publicKey:registered.publicKey.signingPublicKey,
    identityPublicKey:registered.publicKey.publicKey,identityPublicKeySignature:registered.publicKey.identityPublicKeySignature}];
  chat.setSigningKeys(signingKeys); chat.setCacheKeys(true); chat.setRejectUnverified(true);
  const prepared = chat.prepareConversationKeyChange({conversationId:'123:123',
    publicKeys:[{userId:'123',keyVersion:'1',publicKey:keys.identity}]});
  return {chat,prepared,signingKeys};
}

test('real SDK signs and encrypts text; web payloads expose no private key or plaintext',async()=>{
  const {chat,prepared,signingKeys} = await fixture();
  try {
    const text = 'Synthetic confidential test 私信';
    const payload = chat.encryptMessage({conversationId:'123:123',text,
      conversationKey:prepared.conversationKey,conversationKeyVersion:prepared.conversationKeyVersion});
    const event = chat.decryptEvent({eventB64:payload.eventB64,
      conversationKeys:{[prepared.conversationKeyVersion]:prepared.conversationKey}, signingKeys});
    assert.equal(event.type,'message'); assert.equal(event.content.text,text); assert.equal(event.verified,true);
    const wire = sendPayload('123:123',payload);
    assert.equal(wire.message_id,payload.messageId);
    assert.equal(wire.encoded_message_create_event,payload.encodedMessageCreateEvent);
    assert.equal(wire.encoded_message_event_signature,payload.encodedMessageEventSignature);
    assert.ok(!JSON.stringify(wire).includes(text));
    const keys = keyPayload(prepared);
    assert.equal(keys.conversation_participant_keys[0].user_id,'123');
    assert.equal(keys.action_signatures[0].message_event_signature.signature,prepared.actionSignatures[0].messageEventSignature.signature);
    assert.ok(!JSON.stringify(keys).includes(Buffer.from(prepared.conversationKey).toString('base64')));
    const tampered = Uint8Array.from(Buffer.from(payload.eventB64,'base64')); tampered[Math.floor(tampered.length/2)] ^= 1;
    assert.throws(()=>chat.decryptEvent({eventB64:Buffer.from(tampered).toString('base64'),conversationKeys:{[prepared.conversationKeyVersion]:prepared.conversationKey},signingKeys}));
  } finally { prepared.conversationKey.fill(0); chat.free(); }
});

test('history cursors compare numeric IDs without losing precision and omit raw keys',()=>{
  const view = messageView({messages:[{event:{type:'keyChange',sequenceId:'9223372036854775805',conversationKeyVersion:'1700000000001',verified:true}},
    {event:{type:'message',id:'fixture-id',sequenceId:'9223372036854775804',senderId:'123',content:{text:'fixture'},verified:true}}],
    errors:{},conversationKeys:{keys:{private:'never-return'}}});
  assert.equal(view.before,'9223372036854775804'); assert.equal(view.key_before,'1700000000001');
  assert.equal(view.messages.length,1); assert.ok(!JSON.stringify(view).includes('never-return'));
  assert.equal(view.encrypted_ready,true);
});


test('a missing historical key event cannot skip messages when computing pagination',()=>{
  const result = messageView({messages:[
    {originalB64:'missing-key',event:{type:'keyChange',sequenceId:'10',conversationKeyVersion:'1'}},
    {originalB64:'page-message',event:{type:'message',sequenceId:'500',content:{text:'fixture'}}}
  ],errors:{}},['page-message']);
  assert.equal(result.before,'500');
});

test('display accepts only unverified plaintext messages and keeps strict verification for sending',()=>{
  const modes = [];
  const chat = {
    decryptEvents: () => ({messages:[],errors:{0:'signature',1:'signature',2:'signature'}}),
    setRejectUnverified: value => modes.push(value),
    decryptEvent: ({eventB64}) => ({
      plain:{type:'message', verified:false, conversationKeyVersion:null, content:{text:'hello'}},
      encrypted:{type:'message', verified:false, conversationKeyVersion:'42'},
      key:{type:'keyChange', verified:false},
    })[eventB64],
  };
  const decoded = decryptForDisplay(chat,['plain','encrypted','key']);
  assert.deepEqual(modes,[false,true]);
  assert.deepEqual(decoded.messages.map(m=>m.originalB64),['plain']);
  assert.deepEqual(Object.keys(decoded.errors),['1','2']);
  assert.equal(messageView(decoded).messages[0].verified,false);
  assert.equal(messageView(decoded).encrypted_ready,false);
});

test('ordinary messages can be read without unlocking an account',async()=>{
  // Synthetic unencrypted event from the upstream SDK's public test vectors.
  const event = 'CwABAAAAATELAAIAAAALcGxhaW4tbXNnLTELAAMAAAAEMTExMQsABAAAAAkxMTExOjIyMjILAAYAAAANMTcwMDAwMDAwMDAwMAwABwwAAQsAZAAAAHAMAAEMAAELAAEAAAAbZml4dHVyZSB1bmVuY3J5cHRlZCBtZXNzYWdlDwADDAAAAAEMAAELAAEAAAATZml4dHVyZS1wbGFpbi1tZWRpYQsABgAAABdmaXh0dXJlLXBsYWluLW1lZGlhLmJpbgAAAAAAAgBmAQAAAA==';
  const chat = await createChat({getAuthToken:async()=>'',juiceboxModule:{Configuration:class{},Client:class{}}});
  try {
    assert.equal(chat.isUnlocked(),false);
    const decoded=decryptForDisplay(chat,[event]);
    assert.equal(decoded.messages[0].event.content.text,'fixture unencrypted message');
    assert.equal(decoded.messages[0].event.verified,false);
    assert.deepEqual(decoded.errors,{});
    assert.throws(()=>chat.decryptEvent({eventB64:event}));
  } finally { chat.free(); }
});

test('plaintext send matches the captured v7 wire format and carries a valid signature',async()=>{
  const {chat,prepared,signingKeys} = await fixture();
  const field = (type,id,body) => Buffer.concat([Buffer.from([type,id >> 8,id & 255]),body]);
  const bytes = value => { const body=Buffer.from(value); const size=Buffer.alloc(4); size.writeInt32BE(body.length); return Buffer.concat([size,body]); };
  const struct = (...values) => Buffer.concat([...values,Buffer.from([0])]);
  const id='12345678-abcd-4321-abcd-123456789abc', text='Synthetic plaintext 中文';
  try {
    const payload=plaintextPayload(chat,{conversationId:'123:123',senderId:'123',keyVersion:'1',text,messageId:id});
    const create=Buffer.from(payload.encodedMessageCreateEvent,'base64');
    const content=create.subarray(7,7+create.readInt32BE(3));
    const signatureEvent=Buffer.from(payload.encodedMessageEventSignature,'base64');
    const sigLength=signatureEvent.readInt32BE(3);
    const signature=Buffer.from(signatureEvent.subarray(7,7+sigLength).toString(),'base64');
    const signed=`MessageCreateEvent,${id},123,123:123,null,${content.toString('base64').replace(/=+$/,'')}`;
    assert.ok(chat.verify(signingKeys[0].publicKey,new Uint8Array(signature),new TextEncoder().encode(signed)));
    const envelope=struct(field(11,1,bytes('10')),field(11,2,bytes(id)),field(11,3,bytes('123')),
      field(11,4,bytes('123:123')),field(12,7,struct(field(12,1,create))));
    chat.setRejectUnverified(false);
    const decoded=chat.decryptEvent({eventB64:envelope.toString('base64')});
    assert.equal(decoded.content.text,text);
    assert.equal(decoded.verified,false);
    assert.throws(()=>plaintextPayload(chat,{conversationId:'123:999',senderId:'456',keyVersion:'1',text,messageId:id}));
  } finally { prepared.conversationKey.fill(0); chat.free(); }
});

test('new conversations distinguish missing peer keys from missing own keys',()=>{
  const key=(userId,publicKeyVersion)=>({userId,publicKeyVersion,identityPublicKey:'identity',publicKey:'signing'});
  const own=key('123','1');
  const missing=newConversationKeys('123:456','123',[own]);
  assert.equal(missing.missingPeer,true);
  assert.deepEqual(missing.keys,[own]);
  const peerOld=key('456','9'), peerNew=key('456','10');
  const complete=newConversationKeys('123:456','123',[own,peerOld,peerNew]);
  assert.equal(complete.missingPeer,false);
  assert.deepEqual(complete.keys,[own,peerNew]);
  assert.throws(()=>newConversationKeys('123:456','123',[peerNew]),/当前账号/);
  assert.throws(()=>newConversationKeys('123:456','123',[own],true),/历史事件/);
  assert.throws(()=>newConversationKeys('123:456','789',[own]),/当前账号/);
});
