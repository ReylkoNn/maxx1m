import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Integer, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    device_name = Column(String(100), nullable=False)
    public_key = Column(String(500), nullable=False)
    fingerprint = Column(String(100), nullable=False, unique=True)
    is_revoked = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="devices")
    messages = relationship(
        "Message",
        back_populates="receiver_device",
        foreign_keys="Message.receiver_device_id"
    )
    group_memberships = relationship("GroupMember", back_populates="device")


class Message(Base):
    __tablename__ = "messages"

    id = Column(String, primary_key=True, default=generate_uuid)
    sender_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    receiver_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    encrypted_blob = Column(Text, nullable=False)
    signature = Column(Text, nullable=False)
    is_delivered = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    receiver_device = relationship(
        "Device",
        foreign_keys=[receiver_device_id],
        back_populates="messages"
    )


class InviteCode(Base):
    __tablename__ = "invite_codes"

    code = Column(String(50), primary_key=True)
    is_used = Column(Boolean, default=False)
    used_by_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, default=lambda: datetime.now(timezone.utc) + timedelta(days=30))


# ============================================================================
# ГРУППЫ
# ============================================================================

class Group(Base):
    __tablename__ = "groups"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    created_by_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    members = relationship(
        "GroupMember",
        back_populates="group",
        cascade="all, delete-orphan"
    )
    messages = relationship(
        "GroupMessage",
        back_populates="group",
        cascade="all, delete-orphan"
    )
    sender_key_distributions = relationship(
        "SenderKeyDistribution",
        back_populates="group",
        cascade="all, delete-orphan"
    )


class GroupMember(Base):
    __tablename__ = "group_members"

    id = Column(String, primary_key=True, default=generate_uuid)
    group_id = Column(String, ForeignKey("groups.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    role = Column(String(20), default="member")  # owner / member
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Уникальность: одно устройство — один раз в группе
    __table_args__ = (
        UniqueConstraint("group_id", "device_id", name="uq_group_member"),
    )

    group = relationship("Group", back_populates="members")
    device = relationship("Device", back_populates="group_memberships")


class GroupMessage(Base):
    __tablename__ = "group_messages"

    id = Column(String, primary_key=True, default=generate_uuid)
    group_id = Column(String, ForeignKey("groups.id"), nullable=False)
    sender_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    # Один blob зашифрованный SenderKey отправителя — для всех участников
    encrypted_blob = Column(Text, nullable=False)
    signature = Column(Text, nullable=False)
    # Метаданные Sender Keys
    sender_key_id = Column(String(64), nullable=False)
    chain_index = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    group = relationship("Group", back_populates="messages")
    sender_device = relationship("Device")
    # Per-device delivery статус
    deliveries = relationship(
        "GroupMessageDelivery",
        back_populates="message",
        cascade="all, delete-orphan"
    )


class GroupMessageDelivery(Base):
    """
    Per-device delivery статус.
    Каждый участник группы имеет свою запись для каждого сообщения.
    Это гарантирует что оффлайн участники получат сообщение при sync.
    """
    __tablename__ = "group_message_deliveries"

    id = Column(String, primary_key=True, default=generate_uuid)
    message_id = Column(String, ForeignKey("group_messages.id"), nullable=False)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    is_delivered = Column(Boolean, default=False)
    delivered_at = Column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("message_id", "device_id", name="uq_delivery"),
    )

    message = relationship("GroupMessage", back_populates="deliveries")


class SenderKeyDistribution(Base):
    """
    Хранит зашифрованные SenderKey для каждого участника группы.
    Сервер слепой — не знает содержимого ключей.
    sender_key_signature позволяет получателю верифицировать
    что ключ действительно от sender_device_id.
    """
    __tablename__ = "sender_key_distributions"

    id = Column(String, primary_key=True, default=generate_uuid)
    group_id = Column(String, ForeignKey("groups.id"), nullable=False)
    sender_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    recipient_device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    # Зашифрованный SenderKey blob (зашифрован pub key получателя)
    encrypted_sender_key = Column(Text, nullable=False)
    # Ed25519 подпись sender_device — получатель может верифицировать
    sender_key_signature = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint(
            "group_id", "sender_device_id", "recipient_device_id",
            name="uq_sender_key"
        ),
    )

    group = relationship("Group", back_populates="sender_key_distributions")


# ============================================================================
# ФАЙЛЫ — контроль доступа
# ============================================================================
# Раньше файлы лежали в secure_uploads/ и были доступны ЛЮБОМУ, кто знал file_id.
# Теперь каждый файл связан с загрузившим пользователем, а скачивать может
# только устройство из белого списка FileAccess.
# Сервер по-прежнему слепой к содержимому (файл зашифрован клиентом),
# но он контролирует КТО может получить зашифрованный блоб.

class FileRecord(Base):
    """Сам факт загрузки файла. Содержимое на диске, метаданные в БД."""
    __tablename__ = "file_records"

    # file_id совпадает с именем файла на диске (UUID), клиент уже работает с ним
    id = Column(String, primary_key=True)
    owner_user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    size = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Устройство, с которого залили (для аудита)
    uploaded_by_device_id = Column(String, ForeignKey("devices.id"), nullable=True)

    accesses = relationship(
        "FileAccess",
        back_populates="file",
        cascade="all, delete-orphan"
    )


class FileAccess(Base):
    """
    Белый список устройств, которые могут скачивать файл.
    По умолчанию туда попадает:
      - загрузивший файл (его device) — чтобы он видел свои картинки
      - device получателя — чтобы он мог скачать то, что ему отправили
    """
    __tablename__ = "file_access"

    id = Column(String, primary_key=True, default=generate_uuid)
    file_id = Column(String, ForeignKey("file_records.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    granted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("file_id", "device_id", name="uq_file_access"),
    )

    file = relationship("FileRecord", back_populates="accesses")