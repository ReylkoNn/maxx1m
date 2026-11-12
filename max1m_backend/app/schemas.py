from pydantic import BaseModel, Field, ConfigDict, model_validator, UUID4
from datetime import datetime
from typing import Any, Annotated

# ============================================================================
# РЕГИСТРАЦИЯ
# ============================================================================

class RegisterRequest(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_]+$", min_length=3, max_length=30)
    password: str = Field(min_length=8, max_length=1024)
    invite_code: str = Field(min_length=1, max_length=50)
    device_name: str = Field(min_length=1, max_length=100)
    public_key: str = Field(min_length=1, max_length=500)
    fingerprint: str = Field(min_length=1, max_length=100)

class RegisterResponse(BaseModel):
    user_id: str
    device_id: str
    message: str

# ============================================================================
# АВТОРИЗАЦИЯ
# ============================================================================

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=1024)
    device_name: str | None = Field(default=None, max_length=100)
    public_key: str | None = Field(default=None, max_length=500)
    fingerprint: str | None = Field(default=None, max_length=100)
    device_id: str | None = Field(default=None, max_length=64)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    device_id: str
    device_public_key: str


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=8, max_length=1024)
    revoke_other_devices: bool = False


class ChangePasswordResponse(BaseModel):
    status: str = "ok"
    revoked_devices_count: int = 0


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    include_other_devices: bool = False
    only_other_devices: bool = False


class LogoutResponse(BaseModel):
    status: str = "ok"
    invalidated_devices_count: int = 0

# ============================================================================
# УСТРОЙСТВА
# ============================================================================

class DeviceInfo(BaseModel):
    id: str
    device_name: str
    public_key: str
    fingerprint: str
    last_seen: datetime
    model_config = ConfigDict(from_attributes=True)


class OwnDeviceInfo(BaseModel):
    id: str
    device_name: str
    public_key: str
    fingerprint: str
    is_revoked: bool
    is_current: bool
    created_at: datetime
    last_seen: datetime
    model_config = ConfigDict(from_attributes=True)

# ============================================================================
# ЛИЧНЫЕ СООБЩЕНИЯ
# ============================================================================

class MessageSend(BaseModel):
    receiver_device_id: str = Field(min_length=1, max_length=64)
    encrypted_blob: str = Field(min_length=1, max_length=1024 * 1024)
    signature: str = Field(min_length=1, max_length=512)

class ReliableMessageSend(MessageSend):
    client_message_id: UUID4


class MessageDeliveryAck(BaseModel):
    message_ids: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(min_length=1, max_length=100)


class MessageResponse(BaseModel):
    id: str
    sender_device_id: str
    encrypted_blob: str
    signature: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ReliableSendResponse(MessageResponse):
    # Only the sending endpoint needs to echo the destination. Sync responses
    # keep their existing shape for older clients.
    receiver_device_id: str

# ============================================================================
# ПОИСК СОЮЗНИКОВ
# ============================================================================

class DevicePublicInfo(BaseModel):
    device_id: str
    device_name: str
    public_key: str
    fingerprint: str

class UserLookupResponse(BaseModel):
    user_id: str
    username: str
    devices: list[DevicePublicInfo]

# ============================================================================
# ГРУППЫ
# ============================================================================

class SenderKeyEntry(BaseModel):
    """
    Один зашифрованный SenderKey для одного участника.

    sender_device_id — КТО шлёт ключ (обязателен для invite,
    когда каждый участник рассылает свой ключ).
    Для create_group можно опустить (используется создатель).
    """
    sender_device_id: str | None = Field(default=None, min_length=1, max_length=64)
    recipient_device_id: str = Field(min_length=1, max_length=64)
    encrypted_sender_key: str = Field(min_length=1, max_length=16384)
    # Ed25519 подпись отправителя — получатель верифицирует
    sender_key_signature: str = Field(min_length=1, max_length=512)

class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    # device_ids участников (без создателя)
    member_device_ids: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(max_length=100)
    # SenderKey создателя зашифрованный для каждого участника
    sender_keys: list[SenderKeyEntry] = Field(max_length=100)

class GroupMemberInfo(BaseModel):
    device_id: str
    device_name: str
    public_key: str
    role: str
    joined_at: datetime
    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode='before')
    @classmethod
    def extract_device_fields(cls, data: Any) -> Any:
        # Если это ORM объект GroupMember — вытаскиваем из .device
        if hasattr(data, 'device') and data.device is not None:
            return {
                'device_id': data.device_id,
                'device_name': data.device.device_name,
                'public_key': data.device.public_key,
                'role': data.role,
                'joined_at': data.joined_at,
            }
        return data

class GroupInfo(BaseModel):
    id: str
    name: str
    created_by_device_id: str
    epoch: int = 1
    created_at: datetime
    members: list[GroupMemberInfo]
    model_config = ConfigDict(from_attributes=True)

class GroupMessageSend(BaseModel):
    group_id: str = Field(min_length=1, max_length=64)
    encrypted_blob: str = Field(min_length=1, max_length=1024 * 1024)
    signature: str = Field(min_length=1, max_length=512)
    sender_key_id: str = Field(min_length=1, max_length=64)
    chain_index: int = Field(ge=0, le=10_000_000)

class GroupMessageResponse(BaseModel):
    id: str
    group_id: str
    sender_device_id: str
    encrypted_blob: str
    signature: str
    sender_key_id: str
    epoch: int = 1
    chain_index: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class SenderKeyBundle(BaseModel):
    """SenderKey полученный от участника группы."""
    group_id: str
    sender_device_id: str
    encrypted_sender_key: str
    sender_key_signature: str
    epoch: int = 1
    model_config = ConfigDict(from_attributes=True)

class GroupInvite(BaseModel):
    group_id: str = Field(min_length=1, max_length=64)
    new_member_device_id: str = Field(min_length=1, max_length=64)
    # SenderKey от каждого существующего участника
    # зашифрованный pub key нового участника
    sender_keys: list[SenderKeyEntry] = Field(max_length=100)


class GroupV2Create(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    member_device_ids: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        min_length=1, max_length=63
    )
    sender_keys: list[SenderKeyEntry] = Field(min_length=1, max_length=63)


class GroupKeyRotateRequest(BaseModel):
    epoch: int = Field(default=1, ge=1, le=1_000_000)
    sender_keys: list[SenderKeyEntry] = Field(max_length=64)


class GroupV2Invite(BaseModel):
    group_id: str = Field(min_length=1, max_length=64)
    new_member_device_id: str = Field(min_length=1, max_length=64)
    sender_keys: list[SenderKeyEntry] = Field(min_length=1, max_length=64)


class GroupV2MessageSend(BaseModel):
    group_id: str = Field(min_length=1, max_length=64)
    encrypted_blob: str = Field(min_length=1, max_length=256 * 1024)
    signature: str = Field(min_length=1, max_length=512)
    sender_key_id: str = Field(min_length=1, max_length=64)
    epoch: int = Field(default=1, ge=1, le=1_000_000)
    chain_index: int = Field(ge=0, le=10_000_000)