import copy
import json
import pytest
from doubleratchet import AuthenticationFailedException, DuplicateMessageException, DoSProtectionException
from probe import AD, DR_CONFIG, Ratchet, new_identity, copy_identity, copy_ratchet, initial_send, initial_receive

pytestmark = pytest.mark.asyncio


async def session():
    alice, bob = new_identity(), new_identity()
    sender, header, message = await initial_send(alice, bob)
    receiver, content, ad = await initial_receive(bob, header, message)
    assert content == b'initial'
    return sender, receiver, ad


async def test_x3dh_and_ratchet_bidirectional():
    a, b, ad = await session()
    first = await a.encrypt_message(b'hello', ad)
    assert await b.decrypt_message(first, ad) == b'hello'
    reply = await b.encrypt_message(b'world', ad)
    assert await a.decrypt_message(reply, ad) == b'world'


async def test_restart_and_out_of_order():
    a, b, ad = await session()
    packets = [await a.encrypt_message(str(i).encode(), ad) for i in range(3)]
    b = Ratchet.from_json(json.loads(json.dumps(b.json)), **DR_CONFIG)
    assert await b.decrypt_message(packets[2], ad) == b'2'
    b = copy_ratchet(b)
    assert await b.decrypt_message(packets[0], ad) == b'0'
    assert await b.decrypt_message(packets[1], ad) == b'1'
    a = copy_ratchet(a)
    assert await a.decrypt_message(await b.encrypt_message(b'reply', ad), ad) == b'reply'


async def test_duplicate_and_tampering_do_not_corrupt_ratchet():
    a, b, ad = await session()
    msg = await a.encrypt_message(b'auth', ad)
    corrupted = msg._replace(ciphertext=msg.ciphertext[:-1] + bytes([msg.ciphertext[-1] ^ 1]))
    before = copy.deepcopy(b.json)
    with pytest.raises(AuthenticationFailedException):
        await b.decrypt_message(corrupted, ad)
    assert b.json == before
    assert await b.decrypt_message(msg, ad) == b'auth'
    with pytest.raises(DuplicateMessageException):
        await b.decrypt_message(msg, ad)


async def test_associated_data_is_authenticated():
    a, b, ad = await session()
    msg = await a.encrypt_message(b'bound', ad)
    with pytest.raises(AuthenticationFailedException):
        await b.decrypt_message(msg, ad + b' altered')
    assert await b.decrypt_message(msg, ad) == b'bound'


async def test_skip_limit_does_not_mutate_receiver():
    a, b, ad = await session()
    packets = [await a.encrypt_message(b'gap', ad) for _ in range(22)]
    before = copy.deepcopy(b.json)
    with pytest.raises(DoSProtectionException):
        await b.decrypt_message(packets[-1], ad)
    assert before == b.json
    assert await b.decrypt_message(packets[0], ad) == b'gap'


async def test_x3dh_prekey_is_consumed_before_initial_ciphertext_is_authenticated():
    alice, bob = new_identity(), new_identity()
    _, header, msg = await initial_send(alice, bob)
    corrupted = msg._replace(ciphertext=msg.ciphertext[:-1] + bytes([msg.ciphertext[-1] ^ 1]))
    # State.get_shared_secret_passive consumes the OPK before DR authenticates
    # the initial ciphertext. Direct integration would lose the original packet.
    with pytest.raises(AuthenticationFailedException):
        await initial_receive(bob, header, corrupted)
    from x3dh import KeyAgreementException
    with pytest.raises(KeyAgreementException):
        await initial_receive(bob, header, msg)


async def test_x3dh_staged_state_can_be_discarded_after_failed_authentication():
    alice, bob = new_identity(), new_identity()
    _, header, msg = await initial_send(alice, bob)
    corrupted = msg._replace(ciphertext=msg.ciphertext[:-1] + bytes([msg.ciphertext[-1] ^ 1]))
    original = copy.deepcopy(bob.json)
    trial = copy_identity(bob)
    with pytest.raises(AuthenticationFailedException):
        await initial_receive(trial, header, corrupted)
    assert bob.json == original
    received, content, _ = await initial_receive(copy_identity(bob), header, msg)
    assert content == b'initial' and received is not None


async def test_invalid_prekey_signature_is_rejected():
    from x3dh import KeyAgreementException
    alice, bob = new_identity(), new_identity()
    bundle = bob.bundle
    fake = bundle._replace(signed_pre_key_sig=bytes([bundle.signed_pre_key_sig[0] ^ 1]) + bundle.signed_pre_key_sig[1:])
    with pytest.raises(KeyAgreementException):
        await alice.get_shared_secret_active(fake, AD)


async def test_same_ed25519_seed_produces_current_app_identity_public_key():
    from nacl.signing import SigningKey
    from x3dh.identity_key_pair import IdentityKeyPairSeed
    from probe import TestState, X_CONFIG
    identity = SigningKey.generate()
    state = TestState.create(**X_CONFIG, identity_key_pair=IdentityKeyPairSeed(identity.encode()))
    assert state.bundle.identity_key == bytes(identity.verify_key)


async def test_stage_outgoing_state_until_exact_ciphertext_is_durable():
    a, b, ad = await session()
    original = copy.deepcopy(a.json)
    trial = copy_ratchet(a)
    lost = await trial.encrypt_message(b'lost write', ad)
    assert a.json == original
    # Discard trial after simulated failed disk write: retry from original state,
    # and only persist/publish the resulting ciphertext with the successor state.
    retry = copy_ratchet(a)
    committed = await retry.encrypt_message(b'durable write', ad)
    assert await b.decrypt_message(committed, ad) == b'durable write'
    # "lost" cannot also be published: it used the same message key and counter.
    with pytest.raises(DuplicateMessageException):
        await b.decrypt_message(lost, ad)


async def test_large_gap_across_chain_transition_loses_old_keys_in_probe():
    a, b, ad = await session()
    old = [await a.encrypt_message(b'old delayed', ad) for _ in range(22)]
    # A reply advances Alice's DH ratchet before she sends a new-chain message.
    await a.decrypt_message(await b.encrypt_message(b'reply', ad), ad)
    newer = await a.encrypt_message(b'new chain', ad)
    with pytest.warns(UserWarning, match='keys skipped'):
        assert await b.decrypt_message(newer, ad) == b'new chain'
    # Reordering beyond the configured threshold means old messages are lost.
    with pytest.raises(AuthenticationFailedException):
        await b.decrypt_message(old[0], ad)
    assert await b.decrypt_message(await a.encrypt_message(b'after', ad), ad) == b'after'


async def test_real_ratchet_with_transaction_store_retry_and_restart(tmp_path):
    import base64
    import os
    from doubleratchet import EncryptedMessage, Header
    from transaction_store import Store, Conflict
    alice, bob, ad = await session()
    key_a, key_b = os.urandom(32), os.urandom(32)
    sa = Store(tmp_path / 'alice.db', key_a, ('alice', 'test', 'a', 'b'))
    sb = Store(tmp_path / 'bob.db', key_b, ('bob', 'test', 'b', 'a'))
    sa.init(alice.json)
    sb.init(bob.json)
    version, state = sa.snapshot()
    trial = Ratchet.from_json(state, **DR_CONFIG)
    packet = await trial.encrypt_message(b'hello transaction', ad)
    wire = json.dumps({'pub': base64.b64encode(packet.header.ratchet_pub).decode(),
                       'n': packet.header.sending_chain_length,
                       'p': packet.header.previous_sending_chain_length,
                       'cipher': base64.b64encode(packet.ciphertext).decode()}, sort_keys=True)
    def fail(): raise OSError('disk failure')
    with pytest.raises(OSError): sa.commit_outgoing(version, trial.json, 'send-1', wire, {'text': 'hello transaction'}, fail)
    assert sa.snapshot() == (version, state) and sa.get_outgoing('send-1') is None
    sa.commit_outgoing(version, trial.json, 'send-1', wire, {'text': 'hello transaction'})
    # Restart the sender; network retry uses the exact committed bytes, not a
    # second encryption. Crash and fsync behaviour still needs real testing.
    sa = Store(tmp_path / 'alice.db', key_a, ('alice', 'test', 'a', 'b'))
    assert sa.get_outgoing('send-1')['wire'] == wire
    raw = json.loads(wire)
    received = EncryptedMessage(Header(base64.b64decode(raw['pub']), raw['p'], raw['n']), base64.b64decode(raw['cipher']))
    b_version, b_state = sb.snapshot()
    b_trial = Ratchet.from_json(b_state, **DR_CONFIG)
    text = await b_trial.decrypt_message(received, ad)
    with pytest.raises(OSError): sb.commit_incoming(b_version, b_trial.json, 'delivery-1', wire.encode(), {'text': text.decode()}, fail)
    assert sb.snapshot() == (b_version, b_state) and not sb.seen_incoming('delivery-1', wire.encode())
    b_trial = Ratchet.from_json(sb.snapshot()[1], **DR_CONFIG)
    text = await b_trial.decrypt_message(received, ad)
    assert sb.commit_incoming(b_version, b_trial.json, 'delivery-1', wire.encode(), {'text': text.decode()})
    sb = Store(tmp_path / 'bob.db', key_b, ('bob', 'test', 'b', 'a'))
    assert sb.seen_incoming('delivery-1', wire.encode())
    assert sb.get_incoming('delivery-1') == {'text': 'hello transaction'}
    with pytest.raises(Conflict): sb.seen_incoming('delivery-1', wire.encode() + b'changed')
    sa.acknowledge_outgoing('send-1')
    assert sa.get_sent_history('send-1') == {'text': 'hello transaction'}
    a_state = Ratchet.from_json(sa.snapshot()[1], **DR_CONFIG)
    b_state = Ratchet.from_json(sb.snapshot()[1], **DR_CONFIG)
    reply = await b_state.encrypt_message(b'reply', ad)
    assert await a_state.decrypt_message(reply, ad) == b'reply'
