from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QWidget, QApplication, QComboBox, QScrollArea, QMessageBox,
    QLineEdit, QCheckBox
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QPixmap, QPainter, QIcon, QColor
from pathlib import Path
from app.state import state
from app.theme import set_theme, generate_qss, ACTIVE_THEME
from app.contact_keys import safe_local_fingerprint
from app.crypto_box import crypto
from app.voice_cache import voice_cache
from app.webrtc_manager import rtc
from app.workers import (
    ListOwnDevicesWorker,
    RevokeDeviceWorker,
    ChangePasswordWorker,
    LogoutSessionWorker,
)

ICONS_PATH = Path(__file__).parent.parent / "assets" / "icons"


def _render_svg(svg_name: str, color: str, size: int = 16) -> QIcon:
    svg_path = ICONS_PATH / svg_name
    if not svg_path.exists():
        return QIcon()
    try:
        svg_content = svg_path.read_text(encoding="utf-8")
        svg_colored = svg_content.replace("currentColor", color)
        renderer = QSvgRenderer(svg_colored.encode("utf-8"))
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        renderer.render(painter)
        painter.end()
        return QIcon(pixmap)
    except Exception as e:
        print(f"[SVG] Ошибка рендера {svg_name}: {e}")
        return QIcon()


def _render_svg_label(svg_name: str, color: str, size: int = 16) -> QLabel:
    label = QLabel()
    label.setFixedSize(size, size)
    label.setFocusPolicy(Qt.NoFocus)
    # Явно прозрачный фон
    label.setAttribute(Qt.WA_TranslucentBackground, True)
    label.setStyleSheet("background: transparent; border: none;")
    icon = _render_svg(svg_name, color, size)
    label.setPixmap(icon.pixmap(size, size))
    return label


class SettingsScreen(QFrame):
    close_requested = Signal()
    logout_requested = Signal()
    call_audio_prefs_changed = Signal(dict)

    def __init__(self):
        super().__init__()
        self.setObjectName("SettingsScreen")
        self._net_workers = []
        self._devices_account_context = None
        self._own_devices = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- ШАПКА ---
        header = QFrame()
        header.setObjectName("SettingsHeader")
        header.setFixedHeight(76)

        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(32, 0, 32, 0)

        title = QLabel("Настройки")
        title.setObjectName("SettingsMainTitle")

        # Кнопка закрытия — SVG иконка
        self.close_btn = _SvgIconBtn("close_small.svg", size=40, icon_size=14)
        self.close_btn.setObjectName("HeaderIconBtn")
        self.close_btn.clicked.connect(self.close_requested.emit)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.close_btn)

        # --- ВКЛАДКИ ---
        self.tabs = QTabWidget()
        self.tabs.setFocusPolicy(Qt.NoFocus)
        self.tabs.addTab(self._build_general_tab(), "Общие")
        self.tabs.addTab(self._build_security_tab(), "Безопасность")
        self.tabs.addTab(self._build_audio_tab(), "Аудио и Звонки")
        self.tabs.addTab(self._build_theme_tab(), "Оформление")

        layout.addWidget(header)
        layout.addWidget(self.tabs)

    def _build_general_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(40, 30, 40, 30)

        section = self._create_section("Учётная запись")
        username_row, self._username_value = self._create_info_row_with_ref(
            "Имя пользователя:", f"@{state.username}" if state.username else "—"
        )
        device_name_row, self._device_name_value = self._create_info_row_with_ref(
            "Устройство:", state.device_name or "—"
        )
        dev_id = state.device_id if state.device_id else "Неизвестно"
        device_id_row, self._device_id_value = self._create_info_row_with_ref(
            "ID устройства:", dev_id
        )
        section.layout().addLayout(username_row)
        section.layout().addLayout(device_name_row)
        section.layout().addLayout(device_id_row)

        logout_row = QHBoxLayout()
        self.logout_btn = QPushButton("Выйти из сессии")
        self.logout_btn.setObjectName("DangerBtn")
        self.logout_btn.setFocusPolicy(Qt.NoFocus)
        self.logout_btn.clicked.connect(self._on_logout_clicked)
        logout_row.addWidget(self.logout_btn)
        logout_row.addStretch()
        section.layout().addSpacing(8)
        section.layout().addLayout(logout_row)

        cache_section = self._create_section("Локальный кэш медиа")
        cache_size_row, self._voice_cache_size_value = self._create_info_row_with_ref(
            "Кэш голосовых сообщений:", "0.0 МБ"
        )
        cache_section.layout().addLayout(cache_size_row)
        cache_btn_row = QHBoxLayout()
        self.clear_voice_cache_btn = QPushButton("Очистить кэш голосовых…")
        self.clear_voice_cache_btn.setObjectName("SecondaryBtn")
        self.clear_voice_cache_btn.setFocusPolicy(Qt.NoFocus)
        self.clear_voice_cache_btn.clicked.connect(self._on_clear_voice_cache_clicked)
        cache_btn_row.addWidget(self.clear_voice_cache_btn)
        cache_btn_row.addStretch()
        cache_section.layout().addSpacing(6)
        cache_section.layout().addLayout(cache_btn_row)

        layout.addWidget(section)
        layout.addSpacing(16)
        layout.addWidget(cache_section)
        layout.addStretch()
        self.refresh_voice_cache_info()
        return tab

    def refresh_voice_cache_info(self):
        lbl = getattr(self, "_voice_cache_size_value", None)
        vc = globals().get("voice_cache")
        if lbl is None or vc is None:
            return
        try:
            mb = vc.get_cache_size_mb()
            lbl.setText(f"{mb} МБ")
        except Exception:
            lbl.setText("Недоступно")

    def _on_clear_voice_cache_clicked(self) -> bool:
        vc = globals().get("voice_cache")
        if vc is None:
            return False
        answer = QMessageBox.question(
            self,
            "Очистить кэш голосовых сообщений",
            "Удалить все локально кэшированные голосовые сообщения (включая старые офлайн-копии в кэше)?\n\n"
            "История переписки не затрагивается; при воспроизведении записи будут скачаны заново с сервера.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        try:
            vc.clear()
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка очистки кэша", f"Не удалось очистить кэш: {type(exc).__name__}")
            return False
        self.refresh_voice_cache_info()
        return True

    def _on_logout_clicked(self):
        answer = QMessageBox.question(
            self,
            "Выход из сессии",
            "Завершить текущую сессию на этом устройстве?\n"
            "Ключи устройства и локальная зашифрованная история останутся сохранёнными.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.logout_requested.emit()

    def _build_security_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setFocusPolicy(Qt.NoFocus)

        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(18)

        section = self._create_section("End-to-End Шифрование")

        from app.theme import get_theme
        t = get_theme()

        # Статус с иконкой shield
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        shield_label = _render_svg_label(
            "shield_check.svg", t.get("success", "#54caa0"), 18
        )
        status_text = QLabel("Личные чаты используют ключи устройств Curve25519 / Ed25519")
        status_text.setObjectName("SettingsValueLabel")
        status_row.addWidget(shield_label)
        status_row.addWidget(status_text)
        status_row.addStretch()

        try:
            fingerprint = crypto.get_fingerprint()
        except (ValueError, AttributeError):
            fingerprint = "Ключи загружаются..."

        self._fp_box = QLabel(f"Ваш Fingerprint:\n{fingerprint}")
        self._fp_box.setObjectName("SettingsFingerprint")
        self._fp_box.setTextInteractionFlags(Qt.TextSelectableByMouse)

        section.layout().addLayout(status_row)
        section.layout().addWidget(self._fp_box)

        devices_section = self._create_section("Устройства аккаунта")
        controls_row = QHBoxLayout()
        self._devices_status_label = QLabel(
            "Нажмите «Обновить список», чтобы проверить все устройства аккаунта на сервере."
        )
        self._devices_status_label.setObjectName("SettingsInfoLabel")
        self._devices_status_label.setWordWrap(True)
        self.refresh_devices_btn = QPushButton("Обновить список")
        self.refresh_devices_btn.setObjectName("SecondaryBtn")
        self.refresh_devices_btn.setFocusPolicy(Qt.NoFocus)
        self.refresh_devices_btn.clicked.connect(self.request_devices_refresh)
        self.logout_other_sessions_btn = QPushButton("Завершить сессии остальных")
        self.logout_other_sessions_btn.setObjectName("SecondaryBtn")
        self.logout_other_sessions_btn.setFocusPolicy(Qt.NoFocus)
        self.logout_other_sessions_btn.clicked.connect(self.request_logout_other_sessions)
        controls_row.addWidget(self._devices_status_label, 1)
        controls_row.addWidget(self.logout_other_sessions_btn)
        controls_row.addWidget(self.refresh_devices_btn)

        self._devices_list_widget = QWidget()
        self._devices_list_layout = QVBoxLayout(self._devices_list_widget)
        self._devices_list_layout.setContentsMargins(0, 4, 0, 0)
        self._devices_list_layout.setSpacing(8)

        devices_section.layout().addLayout(controls_row)
        devices_section.layout().addWidget(self._devices_list_widget)

        password_section = self._create_section("Смена пароля аккаунта")
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.Password)
        self.current_password_input.setMaxLength(1024)
        self.current_password_input.setPlaceholderText("Текущий пароль")

        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input.setMaxLength(1024)
        self.new_password_input.setPlaceholderText("Новый пароль (минимум 8 символов)")

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setMaxLength(1024)
        self.confirm_password_input.setPlaceholderText("Повторите новый пароль")

        self.revoke_other_devices_cb = QCheckBox(
            "Одновременно отозвать доступ всех остальных устройств аккаунта"
        )
        self.revoke_other_devices_cb.setFocusPolicy(Qt.NoFocus)

        pw_actions_row = QHBoxLayout()
        self._password_status_label = QLabel("")
        self._password_status_label.setObjectName("SettingsInfoLabel")
        self._password_status_label.setWordWrap(True)
        self.change_password_btn = QPushButton("Обновить пароль")
        self.change_password_btn.setObjectName("SecondaryBtn")
        self.change_password_btn.setFocusPolicy(Qt.NoFocus)
        self.change_password_btn.clicked.connect(self.submit_password_change)
        pw_actions_row.addWidget(self._password_status_label, 1)
        pw_actions_row.addWidget(self.change_password_btn)

        password_section.layout().addWidget(self.current_password_input)
        password_section.layout().addWidget(self.new_password_input)
        password_section.layout().addWidget(self.confirm_password_input)
        password_section.layout().addWidget(self.revoke_other_devices_cb)
        password_section.layout().addLayout(pw_actions_row)

        tls_section = self._create_section("Защита от перехвата TLS / подставных CA (SPKI Pinning)")
        self._tls_pin_status_label = QLabel("")
        self._tls_pin_status_label.setObjectName("SettingsInfoLabel")
        self._tls_pin_status_label.setWordWrap(True)
        self._tls_pin_status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.tls_pin_input = QLineEdit()
        self.tls_pin_input.setMaxLength(128)
        self.tls_pin_input.setPlaceholderText("sha256/<Base64> или 64 hex-символа резервного SPKI-ключа")

        tls_btn_row = QHBoxLayout()
        self.pin_live_tls_btn = QPushButton("Закрепить текущий TLS-ключ")
        self.pin_live_tls_btn.setObjectName("SecondaryBtn")
        self.pin_live_tls_btn.setFocusPolicy(Qt.NoFocus)
        self.pin_live_tls_btn.clicked.connect(self.pin_current_server_spki)

        self.add_manual_tls_btn = QPushButton("Добавить пин")
        self.add_manual_tls_btn.setObjectName("SecondaryBtn")
        self.add_manual_tls_btn.setFocusPolicy(Qt.NoFocus)
        self.add_manual_tls_btn.clicked.connect(self.add_manual_tls_pin)

        self.clear_tls_pins_btn = QPushButton("Сбросить пины")
        self.clear_tls_pins_btn.setObjectName("SecondaryBtn")
        self.clear_tls_pins_btn.setFocusPolicy(Qt.NoFocus)
        self.clear_tls_pins_btn.clicked.connect(self.clear_current_server_spki_pins)

        tls_btn_row.addWidget(self.pin_live_tls_btn)
        tls_btn_row.addWidget(self.add_manual_tls_btn)
        tls_btn_row.addWidget(self.clear_tls_pins_btn)
        tls_btn_row.addStretch()

        join_export_row = QHBoxLayout()
        self.join_export_invite_input = QLineEdit()
        self.join_export_invite_input.setMaxLength(128)
        self.join_export_invite_input.setPlaceholderText("Инвайт-код для коллеги (опционально)")
        self.copy_join_link_btn = QPushButton("Скопировать ссылку max1m-join://")
        self.copy_join_link_btn.setObjectName("SecondaryBtn")
        self.copy_join_link_btn.setFocusPolicy(Qt.NoFocus)
        self.copy_join_link_btn.clicked.connect(self.copy_join_link_ui)
        join_export_row.addWidget(self.join_export_invite_input, 1)
        join_export_row.addWidget(self.copy_join_link_btn, 0)

        tls_section.layout().addWidget(self._tls_pin_status_label)
        tls_section.layout().addWidget(self.tls_pin_input)
        tls_section.layout().addLayout(tls_btn_row)
        tls_section.layout().addLayout(join_export_row)
        self.refresh_tls_pin_info()

        vault_section = self._create_section(
            "Локальный сейф Argon2id (Анти-обыск ПК), Автоблокировка и Panic Wipe"
        )
        self._vault_status_label = QLabel("")
        self._vault_status_label.setObjectName("SettingsInfoLabel")
        self._vault_status_label.setWordWrap(True)

        self.vault_master_input = QLineEdit()
        self.vault_master_input.setEchoMode(QLineEdit.Password)
        self.vault_master_input.setMaxLength(1024)
        self.vault_master_input.setPlaceholderText(
            "Мастер-пароль локального сейфа (мин. 8 символов; не хранится в Keyring ОС)"
        )

        self.vault_confirm_input = QLineEdit()
        self.vault_confirm_input.setEchoMode(QLineEdit.Password)
        self.vault_confirm_input.setMaxLength(1024)
        self.vault_confirm_input.setPlaceholderText("Повторите мастер-пароль сейфа")

        self.vault_duress_input = QLineEdit()
        self.vault_duress_input.setEchoMode(QLineEdit.Password)
        self.vault_duress_input.setMaxLength(1024)
        self.vault_duress_input.setPlaceholderText(
            "Опционально: код под принуждением (Duress PIN, мин. 6 символов — мгновенное стирание)"
        )

        auto_lock_row = QHBoxLayout()
        auto_lock_lbl = QLabel("Автоблокировка по неактивности:")
        auto_lock_lbl.setObjectName("SettingsValueLabel")
        self.auto_lock_combo = QComboBox()
        self.auto_lock_combo.setFocusPolicy(Qt.NoFocus)
        for label_txt, sec_val in (
            ("Выключено", 0),
            ("1 минута", 60),
            ("5 минут", 300),
            ("15 минут", 900),
            ("30 минут", 1800),
            ("1 час", 3600),
        ):
            self.auto_lock_combo.addItem(label_txt, sec_val)
        self.auto_lock_combo.currentIndexChanged.connect(self.save_auto_lock_preference_ui)
        auto_lock_row.addWidget(auto_lock_lbl)
        auto_lock_row.addWidget(self.auto_lock_combo)
        auto_lock_row.addStretch()

        vault_btn_row = QHBoxLayout()
        self.enable_vault_btn = QPushButton("Включить / обновить сейф")
        self.enable_vault_btn.setObjectName("SecondaryBtn")
        self.enable_vault_btn.setFocusPolicy(Qt.NoFocus)
        self.enable_vault_btn.clicked.connect(self.configure_local_vault_ui)

        self.disable_vault_btn = QPushButton("Отключить сейф")
        self.disable_vault_btn.setObjectName("SecondaryBtn")
        self.disable_vault_btn.setFocusPolicy(Qt.NoFocus)
        self.disable_vault_btn.clicked.connect(self.disable_local_vault_ui)

        self.lock_now_btn = QPushButton("Заблокировать (Ctrl+Shift+L)")
        self.lock_now_btn.setObjectName("SecondaryBtn")
        self.lock_now_btn.setFocusPolicy(Qt.NoFocus)
        self.lock_now_btn.clicked.connect(self.lock_now_ui)

        self.panic_wipe_btn = QPushButton("Экстренное стирание (Panic Wipe)")
        self.panic_wipe_btn.setObjectName("SecondaryBtn")
        self.panic_wipe_btn.setFocusPolicy(Qt.NoFocus)
        self.panic_wipe_btn.setStyleSheet(
            f"color: {t.get('danger', '#e55c6c')}; border-color: {t.get('danger', '#e55c6c')};"
        )
        self.panic_wipe_btn.clicked.connect(self.trigger_panic_wipe_ui)

        vault_btn_row.addWidget(self.enable_vault_btn)
        vault_btn_row.addWidget(self.disable_vault_btn)
        vault_btn_row.addWidget(self.lock_now_btn)
        vault_btn_row.addWidget(self.panic_wipe_btn)
        vault_btn_row.addStretch()

        from PySide6.QtWidgets import QCheckBox
        self.private_notif_cb = QCheckBox(
            "Приватные уведомления (скрывать имя отправителя и текст сообщений)"
        )
        self.private_notif_cb.setFocusPolicy(Qt.NoFocus)
        self.private_notif_cb.toggled.connect(self.save_private_notifications_ui)

        vault_section.layout().addWidget(self._vault_status_label)
        vault_section.layout().addWidget(self.vault_master_input)
        vault_section.layout().addWidget(self.vault_confirm_input)
        vault_section.layout().addWidget(self.vault_duress_input)
        vault_section.layout().addLayout(auto_lock_row)
        vault_section.layout().addWidget(self.private_notif_cb)
        vault_section.layout().addLayout(vault_btn_row)
        self.refresh_local_vault_info()

        layout.addWidget(section)
        layout.addWidget(tls_section)
        layout.addWidget(vault_section)
        layout.addWidget(password_section)
        layout.addWidget(devices_section)
        layout.addStretch()
        scroll.setWidget(tab)
        return scroll

    def _current_account_context(self):
        account = (
            getattr(state, "username", None),
            getattr(state, "server_url", None),
            getattr(state, "device_id", None),
            getattr(state, "token", None),
        )
        if not all(isinstance(v, str) and v for v in account):
            return None
        return account

    def _clear_devices_rows(self):
        while self._devices_list_layout.count():
            item = self._devices_list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _render_own_devices(self, devices: list):
        self._clear_devices_rows()
        for dev in devices:
            row_frame = QFrame()
            row_frame.setObjectName("SettingsDeviceRow")
            row_layout = QHBoxLayout(row_frame)
            row_layout.setContentsMargins(10, 8, 10, 8)
            row_layout.setSpacing(12)

            is_current = bool(dev.get("is_current"))
            is_revoked = bool(dev.get("is_revoked"))
            claimed_fp = str(dev.get("fingerprint") or "")
            safe_fp_fn = globals().get("safe_local_fingerprint")
            fp_mismatch = bool(dev.get("server_fingerprint_mismatch"))
            if callable(safe_fp_fn):
                computed_fp, is_canonical = safe_fp_fn(dev.get("public_key"), fallback=claimed_fp)
                if is_canonical:
                    if claimed_fp and claimed_fp != computed_fp:
                        fp_mismatch = True
                    fp = computed_fp
                else:
                    fp = claimed_fp
            else:
                fp = claimed_fp
            short_fp = fp if len(fp) <= 24 else f"{fp[:24]}…"
            badge = (
                "это устройство"
                if is_current
                else ("отозвано" if is_revoked else "активно")
            )
            mismatch_warn = " [⚠️ подменён отпечаток сервера]" if fp_mismatch else ""

            info_lbl = QLabel(
                f"{dev.get('device_name', 'Устройство')} [{badge}]{mismatch_warn}\n"
                f"ID: {dev.get('id', '—')}  •  FP: {short_fp}"
            )
            info_lbl.setObjectName("SettingsValueLabel")
            info_lbl.setWordWrap(True)
            info_lbl.setToolTip(f"Fingerprint: {fp}\nDevice ID: {dev.get('id', '')}")
            info_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row_layout.addWidget(info_lbl, 1)

            if not is_current and not is_revoked:
                revoke_btn = QPushButton("Отозвать")
                revoke_btn.setObjectName("DangerBtn")
                revoke_btn.setFocusPolicy(Qt.NoFocus)
                revoke_btn.clicked.connect(
                    lambda _checked=False, d=dict(dev): self._confirm_and_revoke_device(d)
                )
                row_layout.addWidget(revoke_btn)

            self._devices_list_layout.addWidget(row_frame)

    def request_devices_refresh(self) -> bool:
        account = self._current_account_context()
        if account is None:
            self._devices_status_label.setText("Войдите в аккаунт для просмотра списка устройств.")
            return False
        if any(isinstance(w, ListOwnDevicesWorker) and w.isRunning() for w in self._net_workers):
            return False
        self.refresh_devices_btn.setEnabled(False)
        self._devices_status_label.setText("Загрузка списка устройств…")
        expected_pub = None
        crypto_obj = globals().get("crypto")
        get_pub = getattr(crypto_obj, "get_public_key_b64", None)
        if callable(get_pub):
            try:
                expected_pub = get_pub()
            except Exception:
                expected_pub = None
        if isinstance(expected_pub, str) and expected_pub:
            worker = ListOwnDevicesWorker(
                account[1],
                account[3],
                expected_device_id=account[2],
                expected_public_key=expected_pub,
            )
        else:
            worker = ListOwnDevicesWorker(account[1], account[3], expected_device_id=account[2])
        worker.account_context = account
        self._net_workers.append(worker)
        worker.finished.connect(
            lambda ok, data, w=worker: self._on_own_devices_loaded(ok, data, w),
            Qt.QueuedConnection,
        )
        try:
            worker.start()
        except Exception:
            if worker in self._net_workers:
                self._net_workers.remove(worker)
            self.refresh_devices_btn.setEnabled(True)
            raise
        return True

    def _on_own_devices_loaded(self, success: bool, data, worker: ListOwnDevicesWorker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        self.refresh_devices_btn.setEnabled(True)
        if worker.account_context != self._current_account_context():
            return
        if not success or not isinstance(data, list):
            if isinstance(data, str) and data.startswith(("HTTP 401:", "HTTP 403:")):
                win = self.window() if hasattr(self, "window") else None
                inv = getattr(win, "_handle_remote_session_invalidated", None)
                if callable(inv):
                    inv("Сессия истекла или устройство отозвано. Выполните вход снова.")
                    return
            self._devices_status_label.setText(str(data))
            return
        self._devices_account_context = worker.account_context[:3]
        self._own_devices = [dict(item) for item in data]
        self._render_own_devices(self._own_devices)
        active_count = sum(1 for item in self._own_devices if not item.get("is_revoked"))
        self._devices_status_label.setText(
            f"Всего устройств: {len(self._own_devices)} (активных: {active_count})"
        )

    def _confirm_and_revoke_device(self, device: dict) -> bool:
        account = self._current_account_context()
        target_id = device.get("id")
        if (account is None or not isinstance(target_id, str) or not target_id
                or target_id == account[2] or device.get("is_revoked")):
            return False
        if any(isinstance(w, RevokeDeviceWorker) and w.target_device_id == target_id and w.isRunning()
               for w in self._net_workers):
            return False
        claimed_fp = str(device.get("fingerprint") or "—")
        safe_fp_fn = globals().get("safe_local_fingerprint")
        display_fp = safe_fp_fn(device.get("public_key"), fallback=claimed_fp)[0] if callable(safe_fp_fn) else claimed_fp
        answer = QMessageBox.question(
            self,
            "Отозвать устройство",
            f"Отозвать устройство «{device.get('device_name', target_id)}»?\n"
            f"Fingerprint: {display_fp}\n\n"
            "Доступ этого устройства к серверу будет заблокирован необратимо.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        if account != self._current_account_context():
            return False
        self._devices_status_label.setText("Отзыв устройства…")
        worker = RevokeDeviceWorker(account[1], account[3], target_id)
        worker.account_context = account
        self._net_workers.append(worker)
        worker.finished.connect(
            lambda ok, data, w=worker: self._on_device_revoked(ok, data, w),
            Qt.QueuedConnection,
        )
        try:
            worker.start()
        except Exception:
            if worker in self._net_workers:
                self._net_workers.remove(worker)
            raise
        return True

    def _on_device_revoked(self, success: bool, data, worker: RevokeDeviceWorker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if worker.account_context != self._current_account_context():
            return
        if not success:
            self._devices_status_label.setText(str(data))
            QMessageBox.warning(self, "Не удалось отозвать устройство", str(data))
            return
        for item in self._own_devices:
            if item.get("id") == worker.target_device_id:
                item["is_revoked"] = True
        self._render_own_devices(self._own_devices)
        active_count = sum(1 for item in self._own_devices if not item.get("is_revoked"))
        self._devices_status_label.setText(
            f"Устройство отозвано. Активных устройств: {active_count}."
        )

    def request_logout_other_sessions(self) -> bool:
        account = self._current_account_context()
        if account is None:
            self._devices_status_label.setText("Войдите в аккаунт для управления сессиями.")
            return False
        if any(isinstance(w, LogoutSessionWorker) and w.isRunning() for w in self._net_workers):
            return False
        answer = QMessageBox.question(
            self,
            "Завершить сессии остальных устройств",
            "Принудительно завершить активные JWT-сессии и WebSocket-соединения на всех остальных устройствах аккаунта?\n\n"
            "Сами устройства не будут отозваны и смогут войти повторно по паролю.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes or account != self._current_account_context():
            return False
        btn = getattr(self, "logout_other_sessions_btn", None)
        if btn is not None:
            btn.setEnabled(False)
        self._devices_status_label.setText("Завершение сессий остальных устройств…")
        worker = LogoutSessionWorker(account[1], account[3], only_other_devices=True)
        worker.account_context = account
        self._net_workers.append(worker)
        worker.finished.connect(
            lambda ok, data, w=worker: self._on_other_sessions_logged_out(ok, data, w),
            Qt.QueuedConnection,
        )
        try:
            worker.start()
        except Exception:
            if worker in self._net_workers:
                self._net_workers.remove(worker)
            if btn is not None:
                btn.setEnabled(True)
            raise
        return True

    def _on_other_sessions_logged_out(self, success: bool, data, worker: LogoutSessionWorker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        btn = getattr(self, "logout_other_sessions_btn", None)
        if btn is not None:
            btn.setEnabled(True)
        if worker.account_context != self._current_account_context():
            return
        if not success:
            self._devices_status_label.setText(str(data))
            QMessageBox.warning(self, "Не удалось завершить сессии", str(data))
            return
        count = data.get("invalidated_devices_count", 0) if isinstance(data, dict) else 0
        self._devices_status_label.setText(
            f"Активные сессии остальных устройств завершены (затронуто устройств: {count})."
        )

    def _clear_password_inputs(self):
        for attr in ("current_password_input", "new_password_input", "confirm_password_input"):
            field = getattr(self, attr, None)
            if field is not None:
                field.clear()
        cb = getattr(self, "revoke_other_devices_cb", None)
        if cb is not None:
            cb.setChecked(False)

    def submit_password_change(self) -> bool:
        account = self._current_account_context()
        if account is None:
            self._password_status_label.setText("Войдите в аккаунт для смены пароля.")
            return False
        if any(isinstance(w, ChangePasswordWorker) and w.isRunning() for w in self._net_workers):
            return False
        current_pw = self.current_password_input.text()
        new_pw = self.new_password_input.text()
        confirm_pw = self.confirm_password_input.text()
        revoke_others = bool(self.revoke_other_devices_cb.isChecked())

        if not current_pw:
            self._password_status_label.setText("Введите текущий пароль.")
            return False
        if len(new_pw) < 8:
            self._password_status_label.setText("Новый пароль должен содержать не менее 8 символов.")
            return False
        if len(new_pw) > 1024:
            self._password_status_label.setText("Новый пароль слишком длинный.")
            return False
        if new_pw != confirm_pw:
            self._password_status_label.setText("Подтверждение нового пароля не совпадает.")
            return False
        if new_pw == current_pw:
            self._password_status_label.setText("Новый пароль должен отличаться от текущего.")
            return False

        if revoke_others:
            answer = QMessageBox.question(
                self,
                "Смена пароля и отзыв устройств",
                "Сменить пароль и необратимо отозвать доступ всех остальных устройств аккаунта?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return False
            if account != self._current_account_context():
                return False

        self._clear_password_inputs()
        self.change_password_btn.setEnabled(False)
        self._password_status_label.setText("Обновление пароля…")
        worker = ChangePasswordWorker(
            account[1],
            account[3],
            current_pw,
            new_pw,
            revoke_other_devices=revoke_others,
        )
        worker.account_context = account
        self._net_workers.append(worker)
        worker.finished.connect(
            lambda ok, data, w=worker: self._on_password_changed(ok, data, w),
            Qt.QueuedConnection,
        )
        try:
            worker.start()
        except Exception:
            if worker in self._net_workers:
                self._net_workers.remove(worker)
            self.change_password_btn.setEnabled(True)
            raise
        return True

    def _on_password_changed(self, success: bool, data, worker: ChangePasswordWorker):
        worker.wait()
        if worker in self._net_workers:
            self._net_workers.remove(worker)
        if hasattr(self, "change_password_btn"):
            self.change_password_btn.setEnabled(True)
        if worker.account_context != self._current_account_context():
            return
        if not success or not isinstance(data, dict):
            self._password_status_label.setText(str(data))
            QMessageBox.warning(self, "Не удалось сменить пароль", str(data))
            return
        revoked_count = int(data.get("revoked_devices_count", 0))
        if worker.revoke_other_devices and getattr(self, "_own_devices", None):
            current_id = worker.account_context[2]
            for item in self._own_devices:
                if item.get("id") != current_id:
                    item["is_revoked"] = True
            self._render_own_devices(self._own_devices)
            active_count = sum(1 for item in self._own_devices if not item.get("is_revoked"))
            self._devices_status_label.setText(
                f"Всего устройств: {len(self._own_devices)} (активных: {active_count})"
            )
        if revoked_count > 0:
            msg = f"Пароль обновлён. Отозвано остальных устройств: {revoked_count}."
        else:
            msg = "Пароль аккаунта успешно обновлён."
        self._password_status_label.setText(msg)

    def _build_audio_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(40, 30, 40, 30)

        section = self._create_section("Аппаратные устройства")

        from app.theme import get_theme
        t = get_theme()

        # Микрофон
        mic_row = QHBoxLayout()
        mic_row.setSpacing(8)
        mic_icon = _render_svg_label("mic_on.svg", t.get("text_soft", "#a4aab8"), 16)
        mic_lbl = QLabel("Микрофон (Ввод):")
        mic_lbl.setObjectName("SettingsInfoLabel")
        mic_row.addWidget(mic_icon)
        mic_row.addWidget(mic_lbl)
        mic_row.addStretch()

        self.mic_combo = QComboBox()
        self.mic_combo.setFocusPolicy(Qt.NoFocus)

        # Динамики
        spk_row = QHBoxLayout()
        spk_row.setSpacing(8)
        spk_icon = _render_svg_label("headset_on.svg", t.get("text_soft", "#a4aab8"), 16)
        spk_lbl = QLabel("Динамики (Вывод):")
        spk_lbl.setObjectName("SettingsInfoLabel")
        spk_row.addWidget(spk_icon)
        spk_row.addWidget(spk_lbl)
        spk_row.addStretch()

        self.spk_combo = QComboBox()
        self.spk_combo.setFocusPolicy(Qt.NoFocus)

        self._populate_audio_combos()

        self.mic_combo.currentIndexChanged.connect(self._on_mic_changed)
        self.spk_combo.currentIndexChanged.connect(self._on_spk_changed)

        self.audio_status = QLabel("")
        self.audio_status.setObjectName("SettingsInfoLabel")

        section.layout().addLayout(mic_row)
        section.layout().addWidget(self.mic_combo)
        section.layout().addSpacing(15)
        section.layout().addLayout(spk_row)
        section.layout().addWidget(self.spk_combo)
        section.layout().addSpacing(10)
        section.layout().addWidget(self.audio_status)

        net_section = self._create_section("Приватность звонков, Шумодав и Рация")
        self.relay_only_checkbox = QCheckBox(
            "Скрывать мой IP при звонках (Relay-Only через собственный TURN / TURNS:443)"
        )
        self.relay_only_checkbox.setFocusPolicy(Qt.NoFocus)

        ng_lbl = QLabel("Шумоподавление микрофона (VAD / Noise Gate):")
        ng_lbl.setObjectName("SettingsInfoLabel")
        self.noise_gate_combo = QComboBox()
        self.noise_gate_combo.setFocusPolicy(Qt.NoFocus)
        self.noise_gate_combo.addItem("Авто — офис (-45 dBFS)", -45.0)
        self.noise_gate_combo.addItem("Мягкое (-52 dBFS)", -52.0)
        self.noise_gate_combo.addItem("Строгое — шум и клавиатура (-35 dBFS)", -35.0)
        self.noise_gate_combo.addItem("Выключено", "off")

        self.ptt_checkbox = QCheckBox(
            "Режим рации (Push-to-Talk — удерживать клавишу V в голосовой комнате)"
        )
        self.ptt_checkbox.setFocusPolicy(Qt.NoFocus)

        self.call_privacy_status = QLabel("")
        self.call_privacy_status.setObjectName("SettingsInfoLabel")

        self.relay_only_checkbox.toggled.connect(self._on_call_audio_prefs_edited)
        self.noise_gate_combo.currentIndexChanged.connect(self._on_call_audio_prefs_edited)
        self.ptt_checkbox.toggled.connect(self._on_call_audio_prefs_edited)

        net_section.layout().addWidget(self.relay_only_checkbox)
        net_section.layout().addSpacing(10)
        net_section.layout().addWidget(ng_lbl)
        net_section.layout().addWidget(self.noise_gate_combo)
        net_section.layout().addSpacing(10)
        net_section.layout().addWidget(self.ptt_checkbox)
        net_section.layout().addSpacing(6)
        net_section.layout().addWidget(self.call_privacy_status)

        layout.addWidget(section)
        layout.addSpacing(16)
        layout.addWidget(net_section)
        layout.addStretch()
        self._load_call_audio_prefs_ui()
        return tab

    def _load_call_audio_prefs_ui(self):
        if not hasattr(self, "relay_only_checkbox"):
            return
        from app.secure_storage import storage as _sec_storage
        prefs = _sec_storage.get_call_audio_prefs(state.username) if state.username else {}
        self.relay_only_checkbox.blockSignals(True)
        self.noise_gate_combo.blockSignals(True)
        self.ptt_checkbox.blockSignals(True)
        try:
            self.relay_only_checkbox.setChecked(bool(prefs.get("ice_relay_only", False)))
            ng_val = prefs.get("noise_gate_db", -45.0)
            target_data = "off" if ng_val is None else float(ng_val)
            idx = self.noise_gate_combo.findData(target_data)
            self.noise_gate_combo.setCurrentIndex(idx if idx >= 0 else 0)
            self.ptt_checkbox.setChecked(bool(prefs.get("push_to_talk", False)))
        finally:
            self.relay_only_checkbox.blockSignals(False)
            self.noise_gate_combo.blockSignals(False)
            self.ptt_checkbox.blockSignals(False)

    def _on_call_audio_prefs_edited(self, *_args):
        if not state.username:
            return
        from app.ice_config import set_ui_relay_only
        from app.secure_storage import storage as _sec_storage

        relay_only = bool(self.relay_only_checkbox.isChecked())
        ng_raw = self.noise_gate_combo.currentData()
        ng_db = None if ng_raw == "off" else float(ng_raw)
        ptt = bool(self.ptt_checkbox.isChecked())

        set_ui_relay_only(relay_only)
        updates = {
            "ice_relay_only": relay_only,
            "noise_gate_db": ng_db,
            "push_to_talk": ptt,
        }
        _sec_storage.set_call_audio_prefs(state.username, updates)
        mode_note = "IP скрыт (только TURN Relay)" if relay_only else "Прямой P2P + резервный TURN/TURNS:443"
        self.call_privacy_status.setText(f"Сохранено: {mode_note}")
        self.call_audio_prefs_changed.emit(_sec_storage.get_call_audio_prefs(state.username))

    def _populate_audio_combos(self):
        devices = rtc.get_audio_devices()

        # ВАЖНО: блокируем сигналы при заполнении, чтобы не ломать звонок
        self.mic_combo.blockSignals(True)
        self.spk_combo.blockSignals(True)
        try:
            self.mic_combo.clear()
            self.spk_combo.clear()

            self.mic_combo.addItem("По умолчанию (Системный)", None)
            for dev in devices.get("inputs", []):
                self.mic_combo.addItem(dev["name"], dev["index"])

            self.spk_combo.addItem("По умолчанию (Системный)", None)
            for dev in devices.get("outputs", []):
                self.spk_combo.addItem(dev["name"], dev["index"])

            if rtc.input_device_index is not None:
                idx = self.mic_combo.findData(rtc.input_device_index)
                self.mic_combo.setCurrentIndex(idx if idx >= 0 else 0)
            else:
                self.mic_combo.setCurrentIndex(0)

            if rtc.output_device_index is not None:
                idx = self.spk_combo.findData(rtc.output_device_index)
                self.spk_combo.setCurrentIndex(idx if idx >= 0 else 0)
            else:
                self.spk_combo.setCurrentIndex(0)
        finally:
            self.mic_combo.blockSignals(False)
            self.spk_combo.blockSignals(False)

    def refresh(self, fetch_devices: bool = False):
        self._username_value.setText(f"@{state.username}" if state.username else "—")
        self._device_name_value.setText(state.device_name or "—")
        self._device_id_value.setText(state.device_id if state.device_id else "Неизвестно")
        try:
            fingerprint = crypto.get_fingerprint()
        except (ValueError, AttributeError):
            fingerprint = "Ключи загружаются..."
        self._fp_box.setText(f"Ваш Fingerprint:\n{fingerprint}")
        self._populate_audio_combos()
        if hasattr(self, "_load_call_audio_prefs_ui"):
            self._load_call_audio_prefs_ui()
        if hasattr(self, "refresh_voice_cache_info"):
            self.refresh_voice_cache_info()

        if hasattr(self, "_devices_list_layout") and hasattr(self, "_devices_status_label"):
            acct_key = (
                getattr(state, "username", None),
                getattr(state, "server_url", None),
                getattr(state, "device_id", None),
            )
            if getattr(self, "_devices_account_context", None) != acct_key:
                self._devices_account_context = acct_key
                self._own_devices = []
                if hasattr(self, "_clear_password_inputs"):
                    self._clear_password_inputs()
                if hasattr(self, "_password_status_label"):
                    self._password_status_label.setText("")
                if getattr(state, "device_id", None) and hasattr(self, "_render_own_devices"):
                    self._render_own_devices([{
                        "id": state.device_id,
                        "device_name": getattr(state, "device_name", None) or "Текущее устройство",
                        "fingerprint": fingerprint if fingerprint != "Ключи загружаются..." else "—",
                        "is_current": True,
                        "is_revoked": False,
                    }])
                elif hasattr(self, "_clear_devices_rows"):
                    self._clear_devices_rows()
                self._devices_status_label.setText(
                    "Нажмите «Обновить список», чтобы загрузить все устройства с сервера."
                )
        if fetch_devices and hasattr(self, "request_devices_refresh"):
            self.request_devices_refresh()

    def _get_filtered_audio_devices(self) -> dict:
        """
        Возвращает только реальные аудиоустройства.
        Фильтрует виртуальные, правильно декодирует имена на Windows.
        """
        pa = rtc.pa
        if pa is None:
            return {"inputs": [], "outputs": []}
        inputs = []
        outputs = []

        skip_keywords = [
            "microsoft sound mapper",
            "primary sound",
        ]

        seen_input_names = set()
        seen_output_names = set()

        try:
            host_api_count = pa.get_host_api_count()

            # Ищем MME — самые стабильные на Windows
            preferred_api = None
            for i in range(host_api_count):
                api_info = pa.get_host_api_info_by_index(i)
                api_name = api_info.get("name", "").lower()
                if "mme" in api_name:
                    preferred_api = i
                    break

            # Fallback на WASAPI если MME нет
            if preferred_api is None:
                for i in range(host_api_count):
                    api_info = pa.get_host_api_info_by_index(i)
                    api_name = api_info.get("name", "").lower()
                    if "wasapi" in api_name:
                        preferred_api = i
                        break

            for i in range(pa.get_device_count()):
                try:
                    info = pa.get_device_info_by_index(i)
                except Exception:
                    continue

                name_raw = info.get("name", "").strip()
                host_api = info.get("hostApi", -1)

                if preferred_api is not None and host_api != preferred_api:
                    continue

                if not name_raw:
                    continue

                # Декодируем имя устройства
                clean_name = self._decode_device_name(name_raw)

                # Пропускаем мусорные
                name_lower = clean_name.lower()
                if any(kw in name_lower for kw in skip_keywords):
                    continue

                # Пропускаем если имя всё ещё мусор
                if self._is_garbage_name(clean_name):
                    continue

                entry = {"index": i, "name": clean_name}

                if info.get("maxInputChannels", 0) > 0:
                    if clean_name not in seen_input_names:
                        seen_input_names.add(clean_name)
                        inputs.append(entry)

                if info.get("maxOutputChannels", 0) > 0:
                    if clean_name not in seen_output_names:
                        seen_output_names.add(clean_name)
                        outputs.append(entry)

        except Exception as e:
            print(f"[Audio] ❌ Ошибка перечисления: {e}")

        print(f"[Audio] Найдено: {len(inputs)} входов, {len(outputs)} выходов")
        for d in inputs:
            print(f"  IN:  [{d['index']}] {d['name']}")
        for d in outputs:
            print(f"  OUT: [{d['index']}] {d['name']}")

        return {"inputs": inputs, "outputs": outputs}

    @staticmethod
    def _decode_device_name(raw_name: str) -> str:
        """
        PyAudio на Windows возвращает имена в разных кодировках.
        Пробуем несколько вариантов декодирования.
        """
        # Вариант 1: уже нормальный UTF-8
        if all(ord(c) < 128 or ord(c) > 255 for c in raw_name):
            # ASCII или уже UTF-8
            if not any(ord(c) > 127 for c in raw_name):
                return raw_name

        # Вариант 2: latin-1 → utf-8 (самый частый случай на Windows)
        try:
            decoded = raw_name.encode('latin-1').decode('utf-8')
            if not any(ord(c) > 0xFFFF for c in decoded):
                return decoded
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass

        # Вариант 3: latin-1 → cp1251 (русская Windows)
        try:
            decoded = raw_name.encode('latin-1').decode('cp1251')
            return decoded
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass

        # Вариант 4: raw → cp1252 → utf-8
        try:
            decoded = raw_name.encode('cp1252').decode('utf-8')
            return decoded
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass

        # Вариант 5: оставляем только читаемые символы
        cleaned = ''.join(c for c in raw_name if ord(c) >= 32 and ord(c) < 127)
        if cleaned:
            return cleaned

        return raw_name

    @staticmethod
    def _is_garbage_name(name: str) -> bool:
        """Проверяет, состоит ли имя из мусорных символов."""
        if not name:
            return True

        # Считаем долю "нормальных" символов
        normal_chars = sum(
            1 for c in name
            if c.isalnum() or c in ' -_().,:/'
            or '\u0400' <= c <= '\u04FF'  # кириллица
            or '\u4E00' <= c <= '\u9FFF'  # CJK
        )

        ratio = normal_chars / max(len(name), 1)

        # Если меньше 50% нормальных символов — мусор
        return ratio < 0.5

    def _build_theme_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(40, 30, 40, 30)

        section = self._create_section("Выбор темы")

        themes = [
            ("obsidian", "Obsidian — Тёмная графитовая (по умолчанию)"),
            ("frost", "Frost — Светлая дневная"),
            ("rose", "Rose — Мягкая премиальная")
        ]

        self.theme_buttons = []

        for theme_id, text in themes:
            btn = QPushButton(text)
            btn.setObjectName("ThemeSelectBtn")
            btn.setFixedHeight(56)
            btn.setProperty("active", ACTIVE_THEME == theme_id)
            btn.clicked.connect(lambda checked, tid=theme_id: self._change_theme(tid))
            self.theme_buttons.append((theme_id, btn))
            section.layout().addWidget(btn)

        layout.addWidget(section)
        layout.addStretch()
        return tab

    def _create_section(self, title):
        section = QFrame()
        section.setObjectName("SettingsSection")
        layout = QVBoxLayout(section)
        layout.setSpacing(12)
        header = QLabel(title)
        header.setObjectName("SettingsSectionTitle")
        layout.addWidget(header)
        return section

    def _create_info_row_with_ref(self, label_text, value_text):
        row = QHBoxLayout()
        lbl = QLabel(label_text)
        lbl.setObjectName("SettingsInfoLabel")
        lbl.setFixedWidth(160)
        val = QLabel(value_text)
        val.setObjectName("SettingsValueLabel")
        val.setWordWrap(True)
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        row.addWidget(lbl)
        row.addWidget(val)
        row.addStretch()
        return row, val

    def _create_info_row(self, label_text, value_text):
        row, _ = self._create_info_row_with_ref(label_text, value_text)
        return row

    def _change_theme(self, theme_name):
        set_theme(theme_name)
        QApplication.instance().setStyleSheet(generate_qss())

        for tid, btn in self.theme_buttons:
            btn.setProperty("active", tid == theme_name)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        main_window = self.window()
        if hasattr(main_window, 'main_screen'):
            main_screen = main_window.main_screen
            if hasattr(main_screen, 'refresh_message_bubbles'):
                main_screen.refresh_message_bubbles()

    def _on_mic_changed(self, index):
        dev_index = self.mic_combo.itemData(index)
        dev_name = self.mic_combo.currentText()
        rtc.set_input_device(dev_index)
        self.audio_status.setText(f"Микрофон: {dev_name}")

    def _on_spk_changed(self, index):
        dev_index = self.spk_combo.itemData(index)
        dev_name = self.spk_combo.currentText()
        rtc.set_output_device(dev_index)
        self.audio_status.setText(f"Динамики: {dev_name}")

    def refresh_tls_pin_info(self):
        lbl = getattr(self, "_tls_pin_status_label", None)
        if lbl is None:
            return
        srv = getattr(state, "server_url", "") or ""
        if not srv:
            lbl.setText("Сервер не выбран. Пиннинг будет доступен после входа или через MAX1M_TLS_SPKI_PINS.")
            return
        try:
            from app.tls_pinning import normalize_host, resolve_spki_pins_for_host

            host = normalize_host(srv)
            pins = sorted(resolve_spki_pins_for_host(host))
            if pins:
                lbl.setText(
                    f"Узел {host}: закреплено ключей ({len(pins)}):\n" + "\n".join(pins)
                )
            else:
                lbl.setText(
                    f"Узел {host}: SPKI-ключ ещё не закреплён (используется системное хранилище CA)."
                )
        except Exception as exc:
            lbl.setText(f"Ошибка чтения TLS SPKI пинов: {exc}")

    def pin_current_server_spki(self) -> bool:
        account = self._current_account_context()
        if not account:
            QMessageBox.warning(self, "Нет активной сессии", "Войдите в аккаунт перед закреплением ключа сервера.")
            return False
        username, server_url, _, _ = account
        try:
            from app.secure_storage import SecureStorage
            from app.tls_pinning import normalize_host, probe_server_spki_pin

            live_pin = probe_server_spki_pin(server_url)
            host = normalize_host(server_url)
            current_map = SecureStorage.load_tls_pins(username)
            existing = list(current_map.get(host, []))
            if live_pin not in existing:
                existing.append(live_pin)
            current_map[host] = existing
            SecureStorage.save_tls_pins(username, current_map)
            self.refresh_tls_pin_info()
            return True
        except Exception as exc:
            QMessageBox.warning(self, "Не удалось закрепить TLS-ключ", str(exc))
            return False

    def add_manual_tls_pin(self) -> bool:
        account = self._current_account_context()
        if not account:
            QMessageBox.warning(self, "Нет активной сессии", "Войдите в аккаунт перед добавлением SPKI-ключа.")
            return False
        raw_pin = self.tls_pin_input.text().strip() if hasattr(self, "tls_pin_input") else ""
        if not raw_pin:
            return False
        username, server_url, _, _ = account
        try:
            from app.secure_storage import SecureStorage
            from app.tls_pinning import normalize_host, normalize_spki_pin

            norm_pin = normalize_spki_pin(raw_pin)
            host = normalize_host(server_url)
            current_map = SecureStorage.load_tls_pins(username)
            existing = list(current_map.get(host, []))
            if norm_pin not in existing:
                existing.append(norm_pin)
            current_map[host] = existing
            SecureStorage.save_tls_pins(username, current_map)
            self.tls_pin_input.clear()
            self.refresh_tls_pin_info()
            return True
        except Exception as exc:
            QMessageBox.warning(self, "Некорректный SPKI-пин", str(exc))
            return False

    def clear_current_server_spki_pins(self) -> bool:
        account = self._current_account_context()
        if not account:
            return False
        answer = QMessageBox.question(
            self,
            "Сброс привязки TLS-ключа",
            "Удалить сохранённые SPKI-ключи текущего сервера?\n"
            "(Пины из переменной окружения MAX1M_TLS_SPKI_PINS при наличии останутся активными.)",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        username, server_url, _, _ = account
        try:
            from app.secure_storage import SecureStorage
            from app.tls_pinning import normalize_host

            host = normalize_host(server_url)
            current_map = SecureStorage.load_tls_pins(username)
            current_map.pop(host, None)
            SecureStorage.save_tls_pins(username, current_map)
            self.refresh_tls_pin_info()
            return True
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка сброса пинов", str(exc))
            return False

    def copy_join_link_ui(self) -> str:
        account = self._current_account_context()
        if not account:
            QMessageBox.warning(self, "Нет активной сессии", "Войдите в аккаунт перед созданием строки подключения.")
            return ""
        _, server_url, _, _ = account
        try:
            from PySide6.QtGui import QGuiApplication
            from app.onboarding import build_join_link
            from app.tls_pinning import normalize_host, probe_server_spki_pin, resolve_spki_pins_for_host

            host = normalize_host(server_url)
            pins = sorted(resolve_spki_pins_for_host(host))
            if not pins:
                pins = [probe_server_spki_pin(server_url)]
            inv = self.join_export_invite_input.text().strip() if hasattr(self, "join_export_invite_input") else ""
            link = build_join_link(server_url, pins[:4], invite_code=inv)
            cb = QGuiApplication.clipboard()
            if cb is not None:
                cb.setText(link)
            QMessageBox.information(
                self,
                "Ссылка скопирована",
                "Строка подключения max1m-join:// скопирована в буфер обмена.\n\n"
                "Передайте её коллеге: она автоматически пропишет адрес сервера, TLS SPKI Pin и инвайт-код.",
            )
            return link
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка генерации ссылки", str(exc))
            return ""

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_tls_pin_info()
        self.refresh_local_vault_info()
        self.refresh_voice_cache_info()

    def refresh_local_vault_info(self):
        lbl = getattr(self, "_vault_status_label", None)
        if lbl is None:
            return
        username = getattr(state, "username", "") or ""
        if not username:
            lbl.setText(
                "Войдите в профиль для настройки локального сейфа Argon2id, кода под принуждением и автоблокировки."
            )
            return
        try:
            from app.local_vault import is_vault_enabled, is_vault_unlocked
            from app.secure_storage import SecureStorage

            enabled = is_vault_enabled(username)
            unlocked = is_vault_unlocked(username)
            auto_sec = SecureStorage.get_auto_lock_seconds(username)
            combo = getattr(self, "auto_lock_combo", None)
            if combo is not None:
                idx = combo.findData(auto_sec)
                if idx >= 0 and combo.currentIndex() != idx:
                    combo.blockSignals(True)
                    combo.setCurrentIndex(idx)
                    combo.blockSignals(False)
            p_cb = getattr(self, "private_notif_cb", None)
            if p_cb is not None:
                masked = SecureStorage.should_mask_notifications(username)
                p_cb.blockSignals(True)
                p_cb.setChecked(masked)
                p_cb.blockSignals(False)
            if enabled:
                st_str = "разблокирован в RAM" if unlocked else "заблокирован"
                lbl.setText(
                    f"Профиль @{username}: сейф Argon2id АКТИВЕН ({st_str}), системный Keyring ОС очищен.\n"
                    "Горячие клавиши: Ctrl+Shift+L — мгновенная блокировка RAM; "
                    "Ctrl+Shift+Backspace — экстренное уничтожение (Panic Wipe)."
                )
            else:
                lbl.setText(
                    f"Профиль @{username}: сейф отключён (ключи хранятся в системном Keyring ОС).\n"
                    "Включите сейф Argon2id, чтобы изъять ключи из ОС и защитить профиль от криминалистического осмотра ПК."
                )
        except Exception as exc:
            lbl.setText(f"Статус локального сейфа недоступен: {type(exc).__name__}")

    def save_auto_lock_preference_ui(self) -> bool:
        account = self._current_account_context()
        combo = getattr(self, "auto_lock_combo", None)
        if not account or combo is None:
            return False
        sec_val = int(combo.currentData() or 0)
        try:
            from app.secure_storage import SecureStorage

            SecureStorage.set_auto_lock_seconds(account[0], sec_val)
            return True
        except Exception:
            return False

    def save_private_notifications_ui(self, checked: bool = False) -> bool:
        account = self._current_account_context()
        p_cb = getattr(self, "private_notif_cb", None)
        if not account or p_cb is None:
            return False
        try:
            from app.secure_storage import SecureStorage

            return bool(SecureStorage.set_private_notifications(account[0], bool(p_cb.isChecked())))
        except Exception:
            return False

    def _clear_vault_inputs(self):
        for attr in ("vault_master_input", "vault_confirm_input", "vault_duress_input"):
            fld = getattr(self, attr, None)
            if fld is not None:
                fld.clear()

    def configure_local_vault_ui(self) -> bool:
        account = self._current_account_context()
        if not account:
            QMessageBox.warning(self, "Нет активной сессии", "Войдите в аккаунт перед включением локального сейфа.")
            return False
        master_pw = self.vault_master_input.text()
        confirm_pw = self.vault_confirm_input.text()
        duress_pw = self.vault_duress_input.text()
        auto_sec = int(self.auto_lock_combo.currentData() or 300) if hasattr(self, "auto_lock_combo") else 300

        if len(master_pw) < 8:
            QMessageBox.warning(self, "Слишком короткий пароль", "Мастер-пароль сейфа должен содержать минимум 8 символов.")
            return False
        if master_pw != confirm_pw:
            QMessageBox.warning(self, "Пароли не совпадают", "Подтверждение мастер-пароля не совпадает.")
            return False
        if duress_pw:
            if len(duress_pw) < 6:
                QMessageBox.warning(self, "Код под принуждением", "Duress PIN должен содержать минимум 6 символов (либо оставьте поле пустым).")
                return False
            if duress_pw == master_pw:
                QMessageBox.warning(self, "Код под принуждением", "Duress PIN обязан отличаться от мастер-пароля.")
                return False

        self._clear_vault_inputs()
        try:
            from app.local_vault import enable_local_vault
            from app.secure_storage import SecureStorage

            enable_local_vault(
                account[0],
                master_pw,
                duress_password=duress_pw if duress_pw else None,
                auto_lock_seconds=auto_sec,
            )
            SecureStorage.set_auto_lock_seconds(account[0], auto_sec)
            self.refresh_local_vault_info()
            QMessageBox.information(
                self,
                "Локальный сейф активирован",
                "Ключи профиля перенесены в контейнер Argon2id и полностью удалены из системного Keyring ОС.",
            )
            return True
        except Exception as exc:
            QMessageBox.warning(self, "Ошибка настройки сейфа", str(exc))
            return False

    def disable_local_vault_ui(self) -> bool:
        account = self._current_account_context()
        if not account:
            return False
        from PySide6.QtWidgets import QInputDialog
        from app.local_vault import disable_local_vault, is_vault_enabled

        if not is_vault_enabled(account[0]):
            QMessageBox.information(self, "Сейф не активен", "Локальный сейф Argon2id уже отключён для этого профиля.")
            return False
        pw, ok = QInputDialog.getText(
            self,
            "Отключение локального сейфа",
            f"Введите мастер-пароль сейфа @{account[0]} для возврата ключей в системный Keyring ОС:",
            QLineEdit.Password,
        )
        if not ok or not pw:
            return False
        try:
            outcome = disable_local_vault(account[0], pw)
            if outcome == "duress_wiped":
                win = self.window()
                if hasattr(win, "logout_session"):
                    win.logout_session()
                return True
            self.refresh_local_vault_info()
            QMessageBox.information(self, "Сейф отключён", "Ключи возвращены в системное хранилище ОС, файл сейфа перезаписан и удалён.")
            return True
        except Exception as exc:
            QMessageBox.warning(self, "Не удалось отключить сейф", str(exc))
            return False

    def lock_now_ui(self):
        from app.local_vault import lock_all_vaults

        win = self.window()
        if hasattr(win, "logout_session"):
            win.logout_session()
        lock_all_vaults()

    def trigger_panic_wipe_ui(self) -> bool:
        username = getattr(state, "username", "") or None
        answer = QMessageBox.warning(
            self,
            "Экстренное уничтожение данных (Panic Wipe)",
            "ВНИМАНИЕ: Все локальные ключи, история переписки, очереди отправки и кэш профиля "
            "будут двухпроходно перезаписаны случайными байтами и нулями и безвозвратно удалены.\n\n"
            "Продолжить экстренное уничтожение?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        from app.local_vault import execute_panic_wipe

        win = self.window()
        if hasattr(win, "logout_session"):
            win.logout_session()
        execute_panic_wipe(username, wipe_all_profiles=(username is None))
        return True


# ============================================================================
# ВСПОМОГАТЕЛЬНАЯ КНОПКА С SVG
# ============================================================================

class _SvgIconBtn(QPushButton):
    def __init__(self, svg_name: str, size: int = 40, icon_size: int = 16, parent=None):
        super().__init__(parent)
        self._svg_name = svg_name
        self._icon_size = icon_size
        self.setFixedSize(size, size)
        self.setFocusPolicy(Qt.NoFocus)
        self.setText("")
        self._refresh()

    def _refresh(self):
        from app.theme import get_theme
        t = get_theme()
        color = t.get("text_soft", "#a4aab8")
        icon = _render_svg(self._svg_name, color, self._icon_size)
        self.setIcon(icon)
        self.setIconSize(QPixmap(self._icon_size, self._icon_size).size())

    def refresh_theme(self):
        self._refresh()