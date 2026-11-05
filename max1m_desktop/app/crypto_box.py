import hashlib
from nacl.signing import SigningKey, VerifyKey
from nacl.public import Box
from nacl.secret import SecretBox
import nacl.utils
from nacl.encoding import Base64Encoder


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
        self.private_key = SigningKey(b64_key.encode('utf-8'), encoder=Base64Encoder)
        self.public_key = self.private_key.verify_key

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
        encrypted_bytes = crypto_box.encrypt(plaintext.encode('utf-8'))
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
        return decrypted_bytes.decode('utf-8')

    def generate_file_key(self) -> str:
        key = nacl.utils.random(SecretBox.KEY_SIZE)
        return Base64Encoder.encode(key).decode('utf-8')

    def encrypt_file(self, file_data: bytes, key_b64: str) -> bytes:
        key_bytes = Base64Encoder.decode(key_b64.encode('utf-8'))
        box = SecretBox(key_bytes)
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(file_data, nonce)
        return bytes(encrypted)

    def decrypt_file(self, encrypted_data: bytes, key_b64: str) -> bytes:
        clean_key = key_b64.strip()
        key_bytes = Base64Encoder.decode(clean_key.encode('utf-8'))
        box = SecretBox(key_bytes)
        return box.decrypt(encrypted_data)


crypto = CryptoManager()