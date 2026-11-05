from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QWidget, QApplication, QComboBox
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QPixmap, QPainter, QIcon, QColor
from pathlib import Path
from app.state import state
from app.theme import set_theme, generate_qss, ACTIVE_THEME
from app.crypto_box import crypto
from app.webrtc_manager import rtc

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

    def __init__(self):
        super().__init__()
        self.setObjectName("SettingsScreen")

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
        section.layout().addLayout(
            self._create_info_row("Имя пользователя:", f"@{state.username}")
        )
        section.layout().addLayout(
            self._create_info_row("Устройство:", state.device_name)
        )
        dev_id = state.device_id if state.device_id else "Неизвестно"
        section.layout().addLayout(
            self._create_info_row("ID устройства:", dev_id)
        )

        layout.addWidget(section)
        layout.addStretch()
        return tab

    def _build_security_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(40, 30, 40, 30)

        section = self._create_section("End-to-End Шифрование")

        from app.theme import get_theme
        t = get_theme()

        # Статус с иконкой shield
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        shield_label = _render_svg_label(
            "shield_check.svg", t.get("success", "#54caa0"), 18
        )
        status_text = QLabel("Все чаты защищены протоколом Curve25519")
        status_text.setObjectName("SettingsValueLabel")
        status_row.addWidget(shield_label)
        status_row.addWidget(status_text)
        status_row.addStretch()

        try:
            fingerprint = crypto.get_fingerprint()
        except (ValueError, AttributeError):
            fingerprint = "Ключи загружаются..."

        fp_box = QLabel(f"Ваш Fingerprint:\n{fingerprint}")
        fp_box.setObjectName("SettingsFingerprint")
        fp_box.setTextInteractionFlags(Qt.TextSelectableByMouse)

        section.layout().addLayout(status_row)
        section.layout().addWidget(fp_box)

        layout.addWidget(section)
        layout.addStretch()
        return tab

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

        devices = rtc.get_audio_devices()

        # ВАЖНО: блокируем сигналы при заполнении, чтобы не ломать звонок
        self.mic_combo.blockSignals(True)
        self.spk_combo.blockSignals(True)

        self.mic_combo.clear()
        self.spk_combo.clear()

        self.mic_combo.addItem("По умолчанию (Системный)", None)
        for dev in devices["inputs"]:
            self.mic_combo.addItem(dev["name"], dev["index"])

        self.spk_combo.addItem("По умолчанию (Системный)", None)
        for dev in devices["outputs"]:
            self.spk_combo.addItem(dev["name"], dev["index"])

        if rtc.input_device_index is not None:
            idx = self.mic_combo.findData(rtc.input_device_index)
            if idx >= 0:
                self.mic_combo.setCurrentIndex(idx)
        else:
            self.mic_combo.setCurrentIndex(0)

        if rtc.output_device_index is not None:
            idx = self.spk_combo.findData(rtc.output_device_index)
            if idx >= 0:
                self.spk_combo.setCurrentIndex(idx)
        else:
            self.spk_combo.setCurrentIndex(0)

        self.mic_combo.blockSignals(False)
        self.spk_combo.blockSignals(False)

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

        layout.addWidget(section)
        layout.addStretch()
        return tab

    def _get_filtered_audio_devices(self) -> dict:
        """
        Возвращает только реальные аудиоустройства.
        Фильтрует виртуальные, правильно декодирует имена на Windows.
        """
        pa = rtc.pa
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

    def _create_info_row(self, label_text, value_text):
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