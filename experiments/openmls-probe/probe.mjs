// Offline self-test only. Never use with real identities, keys or messages.
import { Provider, Identity, Group } from 'openmls-wasm';
import { randomUUID } from 'node:crypto';

const encoder = new TextEncoder(), decoder = new TextDecoder();
function fixture() {
  const pa = new Provider(), pb = new Provider();
  const alice = new Identity(pa, 'alice-test-only'), bob = new Identity(pb, 'bob-test-only');
  const ga = Group.create_new(pa, alice, randomUUID());
  const add = ga.propose_and_commit_add(pa, alice, bob.key_package(pb));
  ga.merge_pending_commit(pa);
  return {pa, pb, alice, bob, ga, gb: Group.join(pb, add.welcome, ga.export_ratchet_tree())};
}
function rejected(f) { try { f(); return false; } catch { return true; } }

const {pa, pb, alice, bob, ga, gb} = fixture();
const first = ga.create_message(pa, alice, encoder.encode('probe alice to bob'));
const firstOk = decoder.decode(gb.process_message(pb, first)) === 'probe alice to bob';
const replayRejected = rejected(() => gb.process_message(pb, first));
const reply = gb.create_message(pb, bob, encoder.encode('probe bob to alice'));
const twoWay = firstOk && decoder.decode(ga.process_message(pa, reply)) === 'probe bob to alice';

const pc = new Provider(), charlie = new Identity(pc, 'charlie-test-only');
const add = ga.propose_and_commit_add(pa, alice, charlie.key_package(pc));
gb.process_message(pb, add.proposal);
const thirdMemberCommitRejected = rejected(() => gb.process_message(pb, add.commit));

const second = fixture();
const original = second.ga.create_message(second.pa, second.alice, encoder.encode('probe'));
const altered = new Uint8Array(original);
altered[altered.length - 1] ^= 1;
const tamperingRejected = rejected(() => second.gb.process_message(second.pb, altered));
const originalRejectedAfterTamper = rejected(() => second.gb.process_message(second.pb, original));

console.log(JSON.stringify({
  experimental: true,
  usable_for_production: false,
  two_member_exchange: twoWay,
  replay_rejected: replayRejected,
  third_member_commit_rejected: thirdMemberCommitRejected,
  tampering_rejected: tamperingRejected,
  original_rejected_after_tamper: originalRejectedAfterTamper,
  remove_exposed: typeof Group.prototype.remove_members === 'function',
  group_persistence_exposed: typeof Group.prototype.save === 'function' && typeof Group.load === 'function',
}));
