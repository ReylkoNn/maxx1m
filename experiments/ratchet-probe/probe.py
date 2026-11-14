"""ISOLATED STUDY ONLY. Not a wire protocol or production implementation.

All data and identities are synthetic. The actual application never imports this.
"""
from doubleratchet import DoubleRatchet, Header
from doubleratchet.recommended import (
    aead_aes_hmac, diffie_hellman_ratchet_curve25519,
    kdf_hkdf, kdf_separate_hmacs, HashFunction,
)
from x3dh import State, IdentityKeyFormat, HashFunction as X3Hash


class TestState(State):
    # No network and deliberately no persistence: this demonstrates what the
    # application would have to build transactionally, not how to implement it.
    def _publish_bundle(self, bundle):
        pass

    @staticmethod
    def _encode_public_key(key_format, pub):
        # Domain separates the two representations in this synthetic probe.
        return key_format.value.encode('ascii') + b':' + pub


class Ratchet(DoubleRatchet):
    @staticmethod
    def _build_associated_data(ad: bytes, header: Header) -> bytes:
        return (ad + header.ratchet_pub + header.sending_chain_length.to_bytes(8, 'big')
                + header.previous_sending_chain_length.to_bytes(8, 'big'))


class AEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function(): return HashFunction.SHA_512
    @staticmethod
    def _get_info(): return b'Maxx1m experimental AEAD - not production'


class RootKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function(): return HashFunction.SHA_512
    @staticmethod
    def _get_info(): return b'Maxx1m experimental root - not production'


class MessageKDF(kdf_separate_hmacs.KDF):
    @staticmethod
    def _get_hash_function(): return HashFunction.SHA_512_256


DR_CONFIG = dict(diffie_hellman_ratchet_class=diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet,
                 root_chain_kdf=RootKDF, message_chain_kdf=MessageKDF,
                 message_chain_constant=b'\x01\x02', dos_protection_threshold=20,
                 max_num_skipped_message_keys=40, aead=AEAD)
X_CONFIG = dict(identity_key_format=IdentityKeyFormat.ED_25519, hash_function=X3Hash.SHA_256,
                info=b'Maxx1m experimental X3DH - not production',
                pre_key_refill_threshold=1, pre_key_refill_target=4)
AD = b'test-only alice-device to bob-device'


def new_identity():
    return TestState.create(**X_CONFIG)


def copy_identity(state):
    return TestState.from_json(state.json, **X_CONFIG)[0]


def copy_ratchet(state):
    return Ratchet.from_json(state.json, **DR_CONFIG)


async def initial_send(alice, bob, content=b'initial'):
    # A real client MUST compare bundle.identity_key to the user's independently
    # verified identity before using it and the server must atomically claim OPKs.
    secret, ad, header = await alice.get_shared_secret_active(bob.bundle, AD)
    alice_ratchet, message = await Ratchet.encrypt_initial_message(
        **DR_CONFIG, shared_secret=secret, recipient_ratchet_pub=header.signed_pre_key,
        message=content, associated_data=ad)
    return alice_ratchet, header, message


async def initial_receive(bob, header, message):
    secret, ad, signed_pre_key = await bob.get_shared_secret_passive(header, AD)
    ratchet, content = await Ratchet.decrypt_initial_message(
        **DR_CONFIG, shared_secret=secret, own_ratchet_priv=signed_pre_key.priv,
        message=message, associated_data=ad)
    return ratchet, content, ad
