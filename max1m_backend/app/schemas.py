from pydantic import BaseModel, Field, ConfigDict, model_validator
from datetime import datetime
from typing import Any

# ============================================================================
# РЕГИСТРАЦИЯ
# ============================================================================

class RegisterRequest(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_]+$", min_length=3, max_length=30)
    password: str = Field(min_length=8)
    invite_code: str
    device_name: str = Field(min_length=1, max_length=100)
    public_key: str
    fingerprint: str

class RegisterResponse(BaseModel):
    user_id: str
    device_id: str
    message: str

# ============================================================================
# АВТОРИЗАЦИЯ
# ============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str
    device_name: str | None = None
    public_key: str | None = None
    fingerprint: str | None = None
    device_id: str | None = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    device_id: str

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

# ============================================================================
# ЛИЧНЫЕ СООБЩЕНИЯ
# ============================================================================

class MessageSend(BaseModel):
    receiver_device_id: str
    encrypted_blob: str
    signature: str

class MessageResponse(BaseModel):
    id: str
    sender_device_id: str
    encrypted_blob: str
    signature: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

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
    sender_device_id: str | None = None
    recipient_device_id: str
    encrypted_sender_key: str
    # Ed25519 подпись отправителя — получатель верифицирует
    sender_key_signature: str

class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    # device_ids участников (без создателя)
    member_device_ids: list[str]
    # SenderKey создателя зашифрованный для каждого участника
    sender_keys: list[SenderKeyEntry]

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
    created_at: datetime
    members: list[GroupMemberInfo]
    model_config = ConfigDict(from_attributes=True)

class GroupMessageSend(BaseModel):
    group_id: str
    encrypted_blob: str
    signature: str
    sender_key_id: str
    chain_index: int

class GroupMessageResponse(BaseModel):
    id: str
    group_id: str
    sender_device_id: str
    encrypted_blob: str
    signature: str
    sender_key_id: str
    chain_index: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class SenderKeyBundle(BaseModel):
    """SenderKey полученный от участника группы."""
    group_id: str
    sender_device_id: str
    encrypted_sender_key: str
    sender_key_signature: str
    model_config = ConfigDict(from_attributes=True)

class GroupInvite(BaseModel):
    group_id: str
    new_member_device_id: str
    # SenderKey от каждого существующего участника
    # зашифрованный pub key нового участника
    sender_keys: list[SenderKeyEntry]