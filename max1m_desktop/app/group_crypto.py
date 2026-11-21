"""
Protected Group E2EE v2 — Authenticated Ratcheted Sender Keys + Epoch Binding.

Security properties:
1. Per-message forward secrecy within an epoch via one-way HMAC-SHA256 symmetric
   KDF ratchet:
       msg_key   = HMAC-SHA256(chain_key, b"max1m-group-msg-v2\\x00" + be32(idx))
       next_ck   = HMAC-SHA256(chain_key, b"max1m-group-chain-v2\\x00" + be32(idx))
   Advancing chain_key irreversibly erases the ability to derive past msg_keys.
   Out-of-order messages are supported within a bounded window (MAX_SKIP = 256),
   and every consumed skipped key is immediately deleted.
2. Domain & context binding:
   - Each SenderKey distribution bundle is encrypted with Curve25519 Box and signed
     with Ed25519, explicitly binding (v=2, group_id, sender_device_id,
     recipient_device_id, epoch, key_id). Cross-group or cross-recipient replay
     is rejected fail-closed.
   - Each group message AEAD SecretBox ciphertext binds (v=2, group_id,
     sender_device_id, key_id, epoch, chain_index, text), AND the outer envelope
     carries a canonical Ed25519 signature over all header fields + ciphertext.
3. Membership change isolation:
   - Joining or leaving bumps the group epoch; members generate a fresh random
     256-bit chain_key and distribute it only to verified active members.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import struct
from typing import Optional

from nacl.encoding import Base64Encoder
from nacl.secret import SecretBox
from nacl.signing import VerifyKey
from nacl.utils import random as nacl_random

from app.crypto_box import (
    CryptoManager,
    crypto as default_crypto,
    pad_traffic_bytes,
    unpad_traffic_bytes,
)

MAX_SKIP = 256
MAX_SKIPPED_CACHE = 256
MAX_KEY_HISTORY_PER_SENDER = 8
MAX_GROUP_TEXT_CHARS = 32_000
MAX_GROUP_NAME_CHARS = 100
SERVER_GROUP_NAME_PLACEHOLDER = "[E2EE]"
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SAFE_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def _reject_non_finite_json(constant: str):
    raise ValueError(f"Unsupported JSON constant: {constant}")


def _kdf_step(chain_key: bytes, chain_index: int) -> tuple[bytes, bytes]:
    if len(chain_key) != 32 or not (0 <= chain_index <= 10_000_000):
        raise ValueError("Invalid chain state")
    idx_bytes = struct.pack(">I", chain_index)
    msg_key = hmac.new(chain_key, b"max1m-group-msg-v2\x00" + idx_bytes, hashlib.sha256).digest()
    next_ck = hmac.new(chain_key, b"max1m-group-chain-v2\x00" + idx_bytes, hashlib.sha256).digest()
    return msg_key, next_ck


def canonical_group_message_bytes(
    group_id: str,
    sender_device_id: str,
    sender_key_id: str,
    epoch: int,
    chain_index: int,
    encrypted_blob: str,
) -> bytes:
    canonical = json.dumps(
        {
            "blob": encrypted_blob,
            "chain_index": int(chain_index),
            "epoch": int(epoch),
            "group_id": group_id,
            "sender_device_id": sender_device_id,
            "sender_key_id": sender_key_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return b"max1m-group-msg-sig-v2\x00" + canonical


class GroupCrypto:
    def generate_sender_key(self, group_id: str = "", epoch: int = 1) -> dict:
        if group_id and not _SAFE_ID_RE.fullmatch(group_id):
            raise ValueError("Invalid group_id")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise ValueError("Invalid epoch")
        chain_key = nacl_random(32)
        key_id = os.urandom(16).hex()
        return {
            "v": 2,
            "key_id": key_id,
            "group_id": group_id,
            "epoch": int(epoch),
            "chain_key": base64.b64encode(chain_key).decode("ascii"),
            "chain_index": 0,
            "skipped_keys": {},
        }

    @staticmethod
    def export_sender_key_for_peer(sender_key: dict) -> dict:
        """Export current chain state for distribution (never exports local skipped_keys)."""
        ck_b64 = sender_key.get("chain_key") or sender_key.get("key")
        if not isinstance(ck_b64, str):
            raise ValueError("Invalid sender_key")
        raw_ck = base64.b64decode(ck_b64.encode("ascii"), validate=True)
        if len(raw_ck) != 32:
            raise ValueError("Invalid sender_key length")
        key_id = sender_key.get("key_id", "")
        if not isinstance(key_id, str) or not _SAFE_KEY_ID_RE.fullmatch(key_id):
            raise ValueError("Invalid key_id")
        chain_index = sender_key.get("chain_index", 0)
        if isinstance(chain_index, bool) or not isinstance(chain_index, int) or chain_index < 0:
            raise ValueError("Invalid chain_index")
        epoch = int(sender_key.get("epoch", 1) or 1)
        return {
            "v": 2,
            "key_id": key_id,
            "group_id": str(sender_key.get("group_id", "")),
            "epoch": epoch,
            "chain_key": base64.b64encode(raw_ck).decode("ascii"),
            "chain_index": chain_index,
        }

    def encrypt_sender_key_for_member(
        self,
        sender_key: dict,
        member_public_key_b64: str,
        *,
        group_id: str = "",
        sender_device_id: str = "",
        recipient_device_id: str = "",
        group_name: str = "",
        crypto_mgr: Optional[CryptoManager] = None,
    ) -> tuple[str, str]:
        cm = crypto_mgr or default_crypto
        exported = self.export_sender_key_for_peer(sender_key)
        eff_group = group_id or exported.get("group_id", "")
        envelope = {
            "v": 2,
            "group_id": eff_group,
            "sender_device_id": sender_device_id,
            "recipient_device_id": recipient_device_id,
            "epoch": exported["epoch"],
            "sender_key": {**exported, "group_id": eff_group},
        }
        if isinstance(group_name, str):
            clean_gname = "".join(ch for ch in group_name.strip() if ord(ch) >= 0x20)[:MAX_GROUP_NAME_CHARS]
            if clean_gname and clean_gname != SERVER_GROUP_NAME_PLACEHOLDER:
                envelope["group_name"] = clean_gname
        payload = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        result = cm.encrypt_message(payload, member_public_key_b64)
        return result["encrypted_blob"], result["signature"]

    def decrypt_sender_key(
        self,
        encrypted_blob: str,
        signature: str,
        sender_public_key_b64: str,
        *,
        expected_group_id: str = "",
        expected_sender_device_id: str = "",
        expected_recipient_device_id: str = "",
        min_epoch: int = 1,
        crypto_mgr: Optional[CryptoManager] = None,
    ) -> Optional[dict]:
        cm = crypto_mgr or default_crypto
        try:
            if (
                not isinstance(encrypted_blob, str)
                or not 0 < len(encrypted_blob) <= 32768
                or not isinstance(signature, str)
                or not 0 < len(signature) <= 512
                or not isinstance(sender_public_key_b64, str)
                or not sender_public_key_b64
            ):
                return None
            if not cm.verify_signature(encrypted_blob, signature, sender_public_key_b64):
                return None

            decrypted_json = cm.decrypt_message(encrypted_blob, sender_public_key_b64)
            outer = json.loads(decrypted_json, parse_constant=_reject_non_finite_json)
            if not isinstance(outer, dict) or outer.get("v") != 2:
                return None

            if expected_group_id and outer.get("group_id") != expected_group_id:
                return None
            if expected_sender_device_id and outer.get("sender_device_id") not in ("", expected_sender_device_id):
                if outer.get("sender_device_id"):
                    return None
            if expected_sender_device_id and outer.get("sender_device_id") != expected_sender_device_id:
                # Require explicit sender binding whenever outer carries sender_device_id or caller expects it
                if outer.get("sender_device_id") != "":
                    return None
            if expected_recipient_device_id and outer.get("recipient_device_id") not in ("", expected_recipient_device_id):
                return None
            if expected_recipient_device_id and outer.get("recipient_device_id") == "":
                return None

            sk = outer.get("sender_key")
            if not isinstance(sk, dict) or sk.get("v") != 2:
                return None
            key_id = sk.get("key_id", "")
            ck_b64 = sk.get("chain_key", "")
            chain_index = sk.get("chain_index", -1)
            epoch = sk.get("epoch", 0)
            if (
                not isinstance(key_id, str)
                or not _SAFE_KEY_ID_RE.fullmatch(key_id)
                or not isinstance(ck_b64, str)
                or isinstance(chain_index, bool)
                or not isinstance(chain_index, int)
                or not (0 <= chain_index <= 10_000_000)
                or isinstance(epoch, bool)
                or not isinstance(epoch, int)
                or epoch < max(1, int(min_epoch))
            ):
                return None
            if expected_group_id and sk.get("group_id") != expected_group_id:
                return None
            raw_ck = base64.b64decode(ck_b64.encode("ascii"), validate=True)
            if len(raw_ck) != 32:
                return None
            result_sk = {
                "v": 2,
                "key_id": key_id,
                "group_id": str(sk.get("group_id", "")),
                "epoch": epoch,
                "chain_key": base64.b64encode(raw_ck).decode("ascii"),
                "chain_index": chain_index,
                "skipped_keys": {},
            }
            raw_gname = outer.get("group_name")
            if isinstance(raw_gname, str):
                clean_gname = "".join(ch for ch in raw_gname.strip() if ord(ch) >= 0x20)[:MAX_GROUP_NAME_CHARS]
                if clean_gname and clean_gname != SERVER_GROUP_NAME_PLACEHOLDER:
                    result_sk["group_name"] = clean_gname
            return result_sk
        except Exception:
            return None

    def encrypt_group_message(
        self,
        text: str,
        sender_key: dict,
        *,
        group_id: str = "",
        sender_device_id: str = "",
        crypto_mgr: Optional[CryptoManager] = None,
        ttl_seconds: Optional[int] = None,
        msg_id: Optional[str] = None,
    ) -> dict:
        cm = crypto_mgr or default_crypto
        if not isinstance(text, str) or not 0 < len(text) <= MAX_GROUP_TEXT_CHARS:
            raise ValueError("Invalid group message text")
        if not isinstance(sender_key, dict):
            raise ValueError("Invalid sender_key")
        if ttl_seconds is not None:
            if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not (5 <= ttl_seconds <= 30 * 86400):
                raise ValueError("Invalid group message ttl_seconds")
        if msg_id is not None and (not isinstance(msg_id, str) or not 1 <= len(msg_id) <= 256):
            raise ValueError("Invalid group message msg_id")

        eff_group = group_id or str(sender_key.get("group_id", ""))
        if eff_group and sender_key.get("group_id") and sender_key["group_id"] != eff_group:
            raise ValueError("SenderKey belongs to a different group")

        ck_b64 = sender_key.get("chain_key") or sender_key.get("key")
        if not isinstance(ck_b64, str):
            raise ValueError("Missing chain_key")
        chain_key = base64.b64decode(ck_b64.encode("ascii"), validate=True)
        current_index = int(sender_key.get("chain_index", 0))
        epoch = int(sender_key.get("epoch", 1) or 1)
        key_id = str(sender_key["key_id"])

        msg_key, next_ck = _kdf_step(chain_key, current_index)
        box = SecretBox(msg_key)

        inner_dict = {
            "v": 2,
            "group_id": eff_group,
            "sender_device_id": sender_device_id,
            "key_id": key_id,
            "epoch": epoch,
            "chain_index": current_index,
            "text": text,
        }
        if ttl_seconds is not None:
            inner_dict["ttl_seconds"] = ttl_seconds
        if msg_id is not None:
            inner_dict["msg_id"] = msg_id

        inner_payload = json.dumps(
            inner_dict,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        padded_inner = pad_traffic_bytes(inner_payload)
        encrypted_blob = base64.b64encode(box.encrypt(padded_inner)).decode("ascii")

        # Irreversibly ratchet chain_key forward BEFORE returning!
        sender_key["chain_key"] = base64.b64encode(next_ck).decode("ascii")
        sender_key.pop("key", None)
        sender_key["chain_index"] = current_index + 1
        sender_key["v"] = 2
        sender_key["epoch"] = epoch
        if eff_group:
            sender_key["group_id"] = eff_group

        signature_b64 = ""
        if cm and getattr(cm, "private_key", None) is not None and eff_group and sender_device_id:
            canon = canonical_group_message_bytes(
                group_id=eff_group,
                sender_device_id=sender_device_id,
                sender_key_id=key_id,
                epoch=epoch,
                chain_index=current_index,
                encrypted_blob=encrypted_blob,
            )
            sig_raw = cm.private_key.sign(canon).signature
            signature_b64 = Base64Encoder.encode(sig_raw).decode("ascii")

        return {
            "v": 2,
            "key_id": key_id,
            "epoch": epoch,
            "chain_index": current_index,
            "blob": encrypted_blob,
            "signature": signature_b64,
        }

    @staticmethod
    def verify_group_message_signature(
        *,
        group_id: str,
        sender_device_id: str,
        sender_key_id: str,
        epoch: int,
        chain_index: int,
        encrypted_blob: str,
        signature_b64: str,
        sender_public_key_b64: str,
    ) -> bool:
        try:
            if (
                not isinstance(signature_b64, str)
                or not 0 < len(signature_b64) <= 512
                or not isinstance(sender_public_key_b64, str)
                or not sender_public_key_b64
                or not isinstance(encrypted_blob, str)
                or not 0 < len(encrypted_blob) <= 256 * 1024
            ):
                return False
            vk = VerifyKey(sender_public_key_b64.encode("ascii"), encoder=Base64Encoder)
            sig_bytes = Base64Encoder.decode(signature_b64.encode("ascii"))
            canon = canonical_group_message_bytes(
                group_id=group_id,
                sender_device_id=sender_device_id,
                sender_key_id=sender_key_id,
                epoch=epoch,
                chain_index=chain_index,
                encrypted_blob=encrypted_blob,
            )
            vk.verify(canon, sig_bytes)
            return True
        except Exception:
            return False

    def decrypt_group_message_envelope(
        self,
        encrypted: dict,
        sender_key: dict,
        *,
        expected_group_id: str = "",
        expected_sender_device_id: str = "",
        sender_public_key_b64: str = "",
    ) -> Optional[dict]:
        try:
            if not isinstance(encrypted, dict) or not isinstance(sender_key, dict):
                return None
            blob_b64 = encrypted.get("blob") or encrypted.get("encrypted_blob")
            key_id = encrypted.get("key_id") or encrypted.get("sender_key_id")
            msg_index = encrypted.get("chain_index")
            msg_epoch = int(encrypted.get("epoch", sender_key.get("epoch", 1)) or 1)

            if (
                not isinstance(blob_b64, str)
                or not 0 < len(blob_b64) <= 256 * 1024
                or not isinstance(key_id, str)
                or key_id != sender_key.get("key_id")
                or isinstance(msg_index, bool)
                or not isinstance(msg_index, int)
                or not (0 <= msg_index <= 10_000_000)
            ):
                return None

            sk_epoch = int(sender_key.get("epoch", 1) or 1)
            if msg_epoch != sk_epoch:
                return None

            if expected_group_id and sender_key.get("group_id") and sender_key["group_id"] != expected_group_id:
                return None

            # Verify canonical Ed25519 signature when sender_public_key_b64 is supplied.
            sig_b64 = encrypted.get("signature", "")
            if sender_public_key_b64:
                if not self.verify_group_message_signature(
                    group_id=expected_group_id or str(sender_key.get("group_id", "")),
                    sender_device_id=expected_sender_device_id,
                    sender_key_id=key_id,
                    epoch=msg_epoch,
                    chain_index=msg_index,
                    encrypted_blob=blob_b64,
                    signature_b64=sig_b64,
                    sender_public_key_b64=sender_public_key_b64,
                ):
                    return None

            skipped = sender_key.setdefault("skipped_keys", {})
            if not isinstance(skipped, dict):
                skipped = {}
                sender_key["skipped_keys"] = skipped

            cur_index = int(sender_key.get("chain_index", 0))
            ck_b64 = sender_key.get("chain_key")
            if not isinstance(ck_b64, str):
                return None
            cur_ck = base64.b64decode(ck_b64.encode("ascii"), validate=True)

            msg_key: Optional[bytes] = None
            new_skipped = dict(skipped)
            new_ck = cur_ck
            new_index = cur_index

            if msg_index < cur_index:
                idx_str = str(msg_index)
                saved_b64 = new_skipped.pop(idx_str, None)
                if not isinstance(saved_b64, str):
                    # Replay or already-consumed message key -> fail closed!
                    return None
                msg_key = base64.b64decode(saved_b64.encode("ascii"), validate=True)
            else:
                delta = msg_index - cur_index
                if delta > MAX_SKIP:
                    return None
                step_ck = cur_ck
                for step_idx in range(cur_index, msg_index):
                    skipped_mk, step_ck = _kdf_step(step_ck, step_idx)
                    new_skipped[str(step_idx)] = base64.b64encode(skipped_mk).decode("ascii")
                msg_key, new_ck = _kdf_step(step_ck, msg_index)
                new_index = msg_index + 1
                # Bound skipped-key cache size FIFO.
                while len(new_skipped) > MAX_SKIPPED_CACHE:
                    oldest = min(new_skipped.keys(), key=lambda k: int(k) if k.isdigit() else 0)
                    new_skipped.pop(oldest, None)

            raw_cipher = base64.b64decode(blob_b64.encode("ascii"), validate=True)
            plaintext_bytes = SecretBox(msg_key).decrypt(raw_cipher)
            unpadded_bytes = unpad_traffic_bytes(plaintext_bytes)
            inner = json.loads(unpadded_bytes.decode("utf-8"), parse_constant=_reject_non_finite_json)
            if not isinstance(inner, dict) or inner.get("v") != 2:
                return None

            if inner.get("key_id") != key_id or inner.get("chain_index") != msg_index or inner.get("epoch") != msg_epoch:
                return None
            if expected_group_id and inner.get("group_id") != expected_group_id:
                return None
            if expected_sender_device_id and inner.get("sender_device_id") != expected_sender_device_id:
                return None

            text = inner.get("text")
            if not isinstance(text, str) or not 0 < len(text) <= MAX_GROUP_TEXT_CHARS:
                return None

            raw_ttl = inner.get("ttl_seconds")
            ttl_val: Optional[int] = None
            if raw_ttl is not None:
                if isinstance(raw_ttl, bool) or not isinstance(raw_ttl, int) or not (5 <= raw_ttl <= 30 * 86400):
                    return None
                ttl_val = raw_ttl

            raw_mid = inner.get("msg_id")
            mid_val: Optional[str] = None
            if raw_mid is not None:
                if not isinstance(raw_mid, str) or not 1 <= len(raw_mid) <= 256:
                    return None
                mid_val = raw_mid

            # Commit ratchet advancement ONLY after authentic AEAD decryption succeeds!
            sender_key["chain_key"] = base64.b64encode(new_ck).decode("ascii")
            sender_key["chain_index"] = new_index
            sender_key["skipped_keys"] = new_skipped
            res = {"text": text, "ttl_seconds": ttl_val}
            if mid_val is not None:
                res["msg_id"] = mid_val
            return res
        except Exception:
            return None

    def decrypt_group_message(
        self,
        encrypted: dict,
        sender_key: dict,
        *,
        expected_group_id: str = "",
        expected_sender_device_id: str = "",
        sender_public_key_b64: str = "",
    ) -> Optional[str]:
        env = self.decrypt_group_message_envelope(
            encrypted,
            sender_key,
            expected_group_id=expected_group_id,
            expected_sender_device_id=expected_sender_device_id,
            sender_public_key_b64=sender_public_key_b64,
        )
        return env["text"] if isinstance(env, dict) else None


def store_member_sender_key(group_entry: dict, sender_device_id: str, sender_key: dict) -> None:
    """Store a verified peer SenderKey keyed by (sender_device_id -> {key_id: state}),
    keeping up to MAX_KEY_HISTORY_PER_SENDER epochs for delayed sync decryption."""
    peer_map = group_entry.setdefault("sender_keys", {})
    existing = peer_map.get(sender_device_id)
    if not isinstance(existing, dict) or "key_id" in existing:
        by_kid = {}
        if isinstance(existing, dict) and isinstance(existing.get("key_id"), str):
            by_kid[existing["key_id"]] = existing
        peer_map[sender_device_id] = by_kid
    else:
        by_kid = existing

    kid = sender_key["key_id"]
    # Do not reset an already-advanced local ratchet chain if the server returns an older chain_index for the same key_id!
    if kid in by_kid and int(by_kid[kid].get("chain_index", 0)) >= int(sender_key.get("chain_index", 0)):
        return
    by_kid[kid] = sender_key
    while len(by_kid) > MAX_KEY_HISTORY_PER_SENDER:
        oldest_kid = min(by_kid.keys(), key=lambda k: int(by_kid[k].get("epoch", 0)))
        if oldest_kid == kid:
            break
        by_kid.pop(oldest_kid, None)


def lookup_member_sender_key(group_entry: dict, sender_device_id: str, key_id: str) -> Optional[dict]:
    peer_map = group_entry.get("sender_keys") or {}
    slot = peer_map.get(sender_device_id)
    if not isinstance(slot, dict):
        return None
    if slot.get("key_id") == key_id:
        return slot
    cand = slot.get(key_id)
    return cand if isinstance(cand, dict) else None


group_crypto = GroupCrypto()
