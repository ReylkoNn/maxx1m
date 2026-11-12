import hashlib
import struct
from nacl.signing import SigningKey, VerifyKey
from nacl.public import Box
from nacl.secret import SecretBox
import nacl.utils
from nacl.encoding import Base64Encoder

PADDING_MAGIC = b"\x00MXP1"
PADDING_HEADER_LEN = 9  # 5-byte magic + 4-byte big-endian payload length
TRAFFIC_PAD_BUCKETS = (512, 2048, 8192, 32768, 65536)
LARGE_PAD_QUANTUM = 16384


def pad_traffic_bytes(raw_bytes: bytes) -> bytes:
    """Pad UTF-8/binary message bytes to fixed traffic-analysis-resistant buckets."""
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise TypeError("Expected bytes")
    raw = bytes(raw_bytes)
    needed = PADDING_HEADER_LEN + len(raw)
    target = 0
    for bucket in TRAFFIC_PAD_BUCKETS:
        if needed <= bucket:
            target = bucket
            break
    if target == 0:
        rem = needed % LARGE_PAD_QUANTUM
        target = needed if rem == 0 else needed + (LARGE_PAD_QUANTUM - rem)
    pad_len = target - needed
    return PADDING_MAGIC + struct.pack(">I", len(raw)) + raw + (b"\x00" * pad_len)


def unpad_traffic_bytes(decrypted_bytes: bytes) -> bytes:
    """Strip bucket padding; seamlessly accepts pre-padding legacy payloads."""
    if not isinstance(decrypted_bytes, (bytes, bytearray)):
        raise TypeError("Expected bytes")
    buf = bytes(decrypted_bytes)
    if len(buf) >= PADDING_HEADER_LEN and buf[:5] == PADDING_MAGIC:
        (real_len,) = struct.unpack(">I", buf[5:9])
        end = PADDING_HEADER_LEN + real_len
        if end > len(buf):
            raise ValueError("Invalid padded payload length")
        tail = buf[end:]
        if any(tail):
            raise ValueError("Non-zero padding tail")
        return buf[PADDING_HEADER_LEN:end]
    return buf


class CryptoManager:
    def __init__(self):
        self.private_key: SigningKey | None = None
        self.public_key = None

    def generate_new_keypair(self):
        self.private_key = SigningKey.generate()
        self.public_key = self.private_key.verify_key

    def get_public_key_b64(self) -> str:
        if not self.public_key:
            raise ValueError("Ключи не сгенерированы")
        return self.public_key.encode(encoder=Base64Encoder).decode('utf-8')

    def get_private_key_b64(self) -> str:
        if not self.private_key:
            raise ValueError("Ключи не сгенерированы")
        return self.private_key.encode(encoder=Base64Encoder).decode('utf-8')

    def load_private_key(self, b64_key: str):
        if not isinstance(b64_key, str) or not b64_key.strip():
            raise ValueError("Некорректный приватный ключ")
        raw = Base64Encoder.decode(b64_key.strip().encode('utf-8'))
        if len(raw) != 32:
            raise ValueError("Некорректная длина приватного ключа")
        self.private_key = SigningKey(raw)
        self.public_key = self.private_key.verify_key

    def clear(self):
        self.private_key = None
        self.public_key = None

    def get_fingerprint(self) -> str:
        if not self.public_key:
            raise ValueError("Ключи не сгенерированы")
        pub_bytes = self.public_key.encode()
        digest = hashlib.sha256(pub_bytes).hexdigest().upper()
        return ":".join(digest[i:i + 4] for i in range(0, 32, 4))

    def verify_signature(self, ciphertext_b64: str, signature_b64: str, sender_pub_b64: str) -> bool:
        try:
            sender_verify_key = VerifyKey(sender_pub_b64.encode('utf-8'), encoder=Base64Encoder)
            encrypted_bytes = Base64Encoder.decode(ciphertext_b64.encode('utf-8'))
            signature_bytes = Base64Encoder.decode(signature_b64.encode('utf-8'))
            sender_verify_key.verify(encrypted_bytes, signature_bytes)
            return True
        except Exception:
            return False

    def encrypt_message(self, plaintext: str, receiver_pub_b64: str) -> dict:
        if not self.private_key:
            raise ValueError("Нет приватного ключа")
        receiver_verify_key = VerifyKey(receiver_pub_b64.encode('utf-8'), encoder=Base64Encoder)
        receiver_curve_pub = receiver_verify_key.to_curve25519_public_key()
        my_curve_priv = self.private_key.to_curve25519_private_key()
        crypto_box = Box(my_curve_priv, receiver_curve_pub)
        padded_plaintext = pad_traffic_bytes(plaintext.encode('utf-8'))
        encrypted_bytes = crypto_box.encrypt(padded_plaintext)
        signature_bytes = self.private_key.sign(encrypted_bytes).signature
        return {
            "encrypted_blob": Base64Encoder.encode(encrypted_bytes).decode('utf-8'),
            "signature": Base64Encoder.encode(signature_bytes).decode('utf-8')
        }

    def decrypt_message(self, ciphertext_b64: str, sender_pub_b64: str) -> str:
        if not self.private_key:
            raise ValueError("Нет приватного ключа")
        sender_verify_key = VerifyKey(sender_pub_b64.encode('utf-8'), encoder=Base64Encoder)
        sender_curve_pub = sender_verify_key.to_curve25519_public_key()
        my_curve_priv = self.private_key.to_curve25519_private_key()
        crypto_box = Box(my_curve_priv, sender_curve_pub)
        encrypted_bytes = Base64Encoder.decode(ciphertext_b64.encode('utf-8'))
        decrypted_bytes = crypto_box.decrypt(encrypted_bytes)
        return unpad_traffic_bytes(decrypted_bytes).decode('utf-8')

    def generate_file_key(self) -> str:
        key = nacl.utils.random(SecretBox.KEY_SIZE)
        return Base64Encoder.encode(key).decode('utf-8')

    def encrypt_file(self, file_data: bytes, key_b64: str) -> bytes:
        if not isinstance(file_data, (bytes, bytearray)):
            raise ValueError("Некорректные данные файла")
        if not isinstance(key_b64, str) or not key_b64.strip():
            raise ValueError("Некорректный ключ шифрования файла")
        key_bytes = Base64Encoder.decode(key_b64.strip().encode('utf-8'))
        if len(key_bytes) != SecretBox.KEY_SIZE:
            raise ValueError("Некорректная длина ключа файла")
        box = SecretBox(key_bytes)
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(bytes(file_data), nonce)
        return bytes(encrypted)

    def decrypt_file(self, encrypted_data: bytes, key_b64: str) -> bytes:
        if (not isinstance(encrypted_data, (bytes, bytearray))
                or len(encrypted_data) < SecretBox.NONCE_SIZE + SecretBox.MACBYTES):
            raise ValueError("Повреждённый или пустой зашифрованный файл")
        if not isinstance(key_b64, str) or not key_b64.strip():
            raise ValueError("Некорректный ключ расшифровки файла")
        clean_key = key_b64.strip()
        key_bytes = Base64Encoder.decode(clean_key.encode('utf-8'))
        if len(key_bytes) != SecretBox.KEY_SIZE:
            raise ValueError("Некорректная длина ключа файла")
        box = SecretBox(key_bytes)
        return box.decrypt(bytes(encrypted_data))


crypto = CryptoManager()