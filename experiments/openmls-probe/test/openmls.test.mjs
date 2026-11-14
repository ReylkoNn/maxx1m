import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Provider, Identity, Group } from 'openmls-wasm';
import { randomUUID } from 'node:crypto';

const encode = new TextEncoder();
const decode = new TextDecoder();

function fixture() {
  const aliceProvider = new Provider();
  const bobProvider = new Provider();
  const alice = new Identity(aliceProvider, 'alice-test-only');
  const bob = new Identity(bobProvider, 'bob-test-only');
  const aliceGroup = Group.create_new(aliceProvider, alice, randomUUID());
  const bobPackage = bob.key_package(bobProvider);
  const add = aliceGroup.propose_and_commit_add(aliceProvider, alice, bobPackage);
  aliceGroup.merge_pending_commit(aliceProvider);
  const bobGroup = Group.join(bobProvider, add.welcome, aliceGroup.export_ratchet_tree());
  return { aliceProvider, bobProvider, alice, bob, aliceGroup, bobGroup };
}

test('two members exchange encrypted application messages in both directions', () => {
  const {aliceProvider: pa, bobProvider: pb, alice, bob, aliceGroup: ga, bobGroup: gb} = fixture();
  const ciphertext = ga.create_message(pa, alice, encode.encode('hello bob'));
  assert.equal(Buffer.from(ciphertext).includes(Buffer.from('hello bob')), false);
  assert.equal(decode.decode(gb.process_message(pb, ciphertext)), 'hello bob');
  const reply = gb.create_message(pb, bob, encode.encode('hello alice'));
  assert.equal(decode.decode(ga.process_message(pa, reply)), 'hello alice');
  assert.deepEqual(ga.export_key(pa, 'probe-only', new Uint8Array([1]), 32),
                   gb.export_key(pb, 'probe-only', new Uint8Array([1]), 32));
});

test('duplicate valid ciphertext is rejected', () => {
  const {aliceProvider: pa, bobProvider: pb, alice, aliceGroup: ga, bobGroup: gb} = fixture();
  const ciphertext = ga.create_message(pa, alice, encode.encode('hello'));
  assert.equal(decode.decode(gb.process_message(pb, ciphertext)), 'hello');
  assert.throws(() => gb.process_message(pb, ciphertext));
});

test('KNOWN BLOCKER: tampered message can consume the matching receive secret', () => {
  const {aliceProvider: pa, bobProvider: pb, alice, aliceGroup: ga, bobGroup: gb} = fixture();
  const ciphertext = ga.create_message(pa, alice, encode.encode('hello'));
  const tampered = new Uint8Array(ciphertext);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => gb.process_message(pb, tampered));
  // The original message then fails on this version of the experimental binding.
  assert.throws(() => gb.process_message(pb, ciphertext), /secret was deleted/i);
});

test('an unrelated identity cannot consume another device’s welcome', () => {
  const pa = new Provider(), pb = new Provider(), pe = new Provider();
  const alice = new Identity(pa, 'alice-test-only'), bob = new Identity(pb, 'bob-test-only');
  const eve = new Identity(pe, 'eve-test-only');
  eve.key_package(pe); // Exercise a real, but unrelated, key package.
  const ga = Group.create_new(pa, alice, randomUUID());
  const add = ga.propose_and_commit_add(pa, alice, bob.key_package(pb));
  ga.merge_pending_commit(pa);
  assert.throws(() => Group.join(pe, add.welcome, ga.export_ratchet_tree()));
  const gb = Group.join(pb, add.welcome, ga.export_ratchet_tree());
  assert.equal(decode.decode(gb.process_message(pb, ga.create_message(pa, alice, encode.encode('ok')))), 'ok');
});

test('KNOWN BLOCKER: WASM wrapper drops proposal required by third-member commit', () => {
  const {aliceProvider: pa, bobProvider: pb, alice, aliceGroup: ga, bobGroup: gb} = fixture();
  const pc = new Provider(), charlie = new Identity(pc, 'charlie-test-only');
  const add = ga.propose_and_commit_add(pa, alice, charlie.key_package(pc));
  // This binding processes proposals but does not store them for subsequent commits.
  assert.equal(gb.process_message(pb, add.proposal).length, 0);
  assert.throws(() => gb.process_message(pb, add.commit), /proposal queue is missing a proposal/i);
  ga.merge_pending_commit(pa);
  const gc = Group.join(pc, add.welcome, ga.export_ratchet_tree());
  const ciphertext = ga.create_message(pa, alice, encode.encode('new epoch'));
  assert.equal(decode.decode(gc.process_message(pc, ciphertext)), 'new epoch');
  assert.throws(() => gb.process_message(pb, ciphertext));
});

test('binding does not expose remove or durable group/identity serialization', () => {
  assert.equal(typeof Group.prototype.remove_members, 'undefined');
  assert.equal(typeof Group.prototype.save, 'undefined');
  assert.equal(typeof Group.load, 'undefined');
  assert.equal(typeof Identity.prototype.serialize, 'undefined');
});

test('KNOWN BLOCKER: malformed message traps and leaves the group object unusable', () => {
  const {aliceProvider: pa, bobProvider: pb, alice, aliceGroup: ga, bobGroup: gb} = fixture();
  assert.throws(() => gb.process_message(pb, new Uint8Array([0])), WebAssembly.RuntimeError);
  const valid = ga.create_message(pa, alice, encode.encode('after malformed input'));
  assert.throws(() => gb.process_message(pb, valid), /recursive use of an object/i);
});

test.todo('existing participants can process a third member’s proposal and commit');
test.todo('removed member cannot decrypt new-epoch messages');
test.todo('group and identity survive restart with atomic state storage');
test.todo('corrupt network input cannot poison an otherwise valid session');
