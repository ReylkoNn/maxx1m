"""
Max1m Theme System
==================
Централизованная система тем с поддержкой Obsidian, Frost, Rose.
"""

from typing import Literal

# ============================================================================
# АКТИВНАЯ ТЕМА
# ============================================================================
ACTIVE_THEME: Literal["obsidian", "frost", "rose"] = "obsidian"

# ============================================================================
# ПАЛИТРЫ ТЕМ
# ============================================================================

THEMES = {
    "obsidian": {
        "bg_main": "#060708",
        "bg_sidebar": "rgba(11, 12, 14, 0.96)",
        "bg_topbar": "rgba(14, 15, 18, 0.96)",
        "bg_panel": "#111317",
        "bg_panel_2": "#161920",
        "bg_card": "rgba(12, 14, 18, 0.97)",
        "bg_input": "rgba(15, 18, 23, 0.98)",
        "bg_input_hover": "rgba(17, 20, 25, 1.0)",
        "bg_input_focus": "rgba(18, 21, 27, 1.0)",
        "bg_button": "rgba(14, 17, 22, 0.98)",
        "bg_button_hover": "rgba(18, 22, 28, 1.0)",

        "bg_bubble_in": "#1a1e26",
        "bg_bubble_out_start": "rgba(102, 110, 138, 0.32)",
        "bg_bubble_out_end": "rgba(128, 137, 175, 0.24)",

        "line_soft": "rgba(34, 39, 48, 0.98)",
        "line_strong": "rgba(42, 48, 58, 1.0)",
        "line_focus": "rgba(78, 90, 118, 0.82)",

        "text_main": "#f8fafb",
        "text_soft": "#a4aab8",
        "text_dim": "#777e8e",
        "text_placeholder": "#6f7787",

        "accent_start": "rgba(108, 116, 138, 0.96)",
        "accent_end": "rgba(136, 144, 170, 0.96)",
        "accent_border": "rgba(78, 86, 106, 0.98)",
        "accent": "#6c748a",
        "success": "#54caa0",
        "danger": "#ff7b8d",
        "warning": "#ffc16a",

        "selection_bg": "rgba(92, 104, 136, 0.38)",
        "selection_fg": "#f4f7fb",
        "screen_share_active": "#00d4ff",
        "screen_share_bg": "rgba(0, 212, 255, 0.12)",
        "screen_share_border": "rgba(0, 212, 255, 0.45)",
    },

    "frost": {
        "bg_main": "#eef3fb",
        "bg_sidebar": "rgba(245, 248, 253, 0.90)",
        "bg_topbar": "rgba(248, 250, 255, 0.92)",
        "bg_panel": "#ffffff",
        "bg_panel_2": "#f3f6fb",
        "bg_card": "#ffffff",
        "bg_input": "#f8f9fc",
        "bg_input_hover": "#f3f5f9",
        "bg_input_focus": "#eef1f7",
        "bg_button": "#f5f7fb",
        "bg_button_hover": "#edf0f6",

        "bg_bubble_in": "#ffffff",
        "bg_bubble_out_start": "rgba(205, 225, 255, 0.95)",
        "bg_bubble_out_end": "rgba(226, 237, 255, 0.95)",

        "line_soft": "rgba(38, 57, 97, 0.10)",
        "line_strong": "rgba(38, 57, 97, 0.16)",
        "line_focus": "rgba(95, 135, 255, 0.42)",

        "text_main": "#162033",
        "text_soft": "#5f6d86",
        "text_dim": "#7f8ca4",
        "text_placeholder": "#9aa7be",

        "accent_start": "#5f87ff",
        "accent_end": "#6ab9ff",
        "accent_border": "rgba(95, 135, 255, 0.28)",
        "accent": "#5f87ff",
        "success": "#17b989",
        "danger": "#e35c78",
        "warning": "#d49a3a",

        "selection_bg": "rgba(95, 135, 255, 0.22)",
        "selection_fg": "#162033",
        "screen_share_active": "#0088ff",
        "screen_share_bg": "rgba(0, 136, 255, 0.15)",
        "screen_share_border": "rgba(0, 136, 255, 0.55)",
    },

    "rose": {
        "bg_main": "#f7eef3",
        "bg_sidebar": "rgba(252, 246, 249, 0.90)",
        "bg_topbar": "rgba(255, 250, 252, 0.92)",
        "bg_panel": "#fffafd",
        "bg_panel_2": "#f8eef4",
        "bg_card": "#fffafd",
        "bg_input": "#fdf6fa",
        "bg_input_hover": "#f9f2f6",
        "bg_input_focus": "#f5eef3",
        "bg_button": "#faf4f7",
        "bg_button_hover": "#f4eef2",

        "bg_bubble_in": "#ffffff",
        "bg_bubble_out_start": "rgba(211, 139, 179, 0.25)",
        "bg_bubble_out_end": "rgba(181, 140, 207, 0.20)",

        "line_soft": "rgba(109, 74, 98, 0.10)",
        "line_strong": "rgba(109, 74, 98, 0.16)",
        "line_focus": "rgba(211, 139, 179, 0.42)",

        "text_main": "#352534",
        "text_soft": "#7f667b",
        "text_dim": "#a18899",
        "text_placeholder": "#b89aab",

        "accent_start": "#d38bb3",
        "accent_end": "#b58ccf",
        "accent_border": "rgba(211, 139, 179, 0.28)",
        "accent": "#d38bb3",
        "success": "#3ead88",
        "danger": "#d06b8c",
        "warning": "#c99262",

        "selection_bg": "rgba(211, 139, 179, 0.22)",
        "selection_fg": "#352534",
        "screen_share_active": "#e36ba8",
        "screen_share_bg": "rgba(227, 107, 168, 0.14)",
        "screen_share_border": "rgba(227, 107, 168, 0.50)",
    },
}


# ============================================================================
# ГЕТТЕРЫ ТЕМЫ
# ============================================================================

def get_theme() -> dict:
    return THEMES[ACTIVE_THEME]


def get_theme_name() -> str:
    return ACTIVE_THEME


def set_theme(theme_name: Literal["obsidian", "frost", "rose"]):
    global ACTIVE_THEME
    ACTIVE_THEME = theme_name


# ============================================================================
# ГЕНЕРАТОР QSS
# ============================================================================

def generate_qss(theme_name: str = None) -> str:
    if theme_name is None:
        theme_name = ACTIVE_THEME

    t = THEMES[theme_name]

    return f"""
/* ============================================================================
   MAX1M GLOBAL STYLESHEET — THEME: {{theme_name.upper()}}
   ============================================================================ */

QWidget {{
    background: {t['bg_main']};
    color: {t['text_main']};
    font-family: "Segoe UI", "SF Pro Display", "Roboto", sans-serif;
    font-size: 14px;
    outline: none;
    selection-background-color: {t['selection_bg']};
    selection-color: {t['selection_fg']};
}}

/* ============================================================================
   WINDOW ROOT
   ============================================================================ */

QFrame#WindowRoot {{
    background: {t['bg_main']};
}}

/* ============================================================================
   TITLEBAR
   ============================================================================ */

QFrame#TitleBar {{
    background: {t['bg_topbar']};
    border: none;
    border-bottom: 1px solid {t['line_soft']};
}}

QLabel#TitleBarTitle {{
    color: {t['text_soft']};
    font-size: 13px;
    font-weight: 600;
    background: transparent;
    letter-spacing: 0.5px;
}}

QPushButton#TitleBarButton {{
    background: transparent;
    border: none;
    outline: none;
    color: {t['text_soft']};
    min-width: 48px;
    max-width: 48px;
    min-height: 40px;
    max-height: 40px;
    font-size: 14px;
    font-weight: 500;
    border-radius: 0px;
}}

QPushButton#TitleBarButton:hover {{
    background: {t['bg_panel_2']};
    color: {t['text_main']};
}}

QPushButton#CloseButton {{
    background: transparent;
    border: none;
    outline: none;
    color: {t['text_soft']};
    min-width: 48px;
    max-width: 48px;
    min-height: 40px;
    max-height: 40px;
    font-size: 14px;
    font-weight: 500;
    border-radius: 0px;
}}

QPushButton#CloseButton:hover {{
    background: {t['danger']};
    color: #ffffff;
}}

/* ============================================================================
   AUTH SCREEN
   ============================================================================ */

QFrame#AmbientCard {{
    background: {t['bg_sidebar']};
    border: 1px solid {t['line_soft']};
    border-radius: 24px;
}}

QLabel#AmbientTitle {{
    color: {t['text_main']};
    font-size: 18px;
    font-weight: 700;
    background: transparent;
}}

QLabel#AmbientText {{
    color: {t['text_dim']};
    font-size: 14px;
    background: transparent;
}}

/* ============================================================================
   AUTH CARD
   ============================================================================ */

QFrame#AuthCard {{
    background: {t['bg_card']};
    border: 1px solid {t['line_soft']};
    border-radius: 30px;
}}

QLabel#BrandTitle {{
    color: {t['text_main']};
    font-size: 44px;
    font-weight: 700;
    background: transparent;
}}

QLabel#BrandSubtitle {{
    color: {t['text_placeholder']};
    font-size: 13px;
    letter-spacing: 1.8px;
    background: transparent;
}}

QLabel#FieldLabel {{
    color: {t['text_soft']};
    font-size: 15px;
    font-weight: 600;
    background: transparent;
}}

QLabel#HintLabel {{
    color: {t['text_dim']};
    font-size: 14px;
    background: transparent;
}}

QFrame#InputBlock {{
    background: transparent;
    border: none;
}}

/* ============================================================================
   INPUT FIELDS
   ============================================================================ */

QLineEdit {{
    background: {t['bg_input']};
    border: 1px solid {t['line_soft']};
    border-radius: 18px;
    padding-left: 18px;
    padding-right: 18px;
    color: {t['text_main']};
    font-size: 15px;
    min-height: 56px;
}}

QLineEdit:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_strong']};
}}

QLineEdit:focus {{
    background: {t['bg_input_focus']};
    border: 1px solid {t['line_focus']};
}}

/* ============================================================================
   BUTTONS — BASE
   ============================================================================ */

QPushButton#PrimaryButton {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']},
        stop:1 {t['accent_end']}
    );
    color: {"#ffffff" if theme_name == "obsidian" else t['text_main']};
    border: 1px solid {t['accent_border']};
    border-radius: 18px;
    min-height: 56px;
    font-size: 15px;
    font-weight: 700;
    outline: none;
}}

QPushButton#PrimaryButton:hover {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_end']},
        stop:1 {t['accent_start']}
    );
}}

QPushButton#PrimaryButton:pressed {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']},
        stop:1 {t['accent_end']}
    );
    border: 2px solid {t['accent_start']};
}}

QPushButton#PrimaryButton:disabled {{
    background: {t['bg_button']};
    color: {t['text_dim']};
    border: 1px solid {t['line_soft']};
}}

QPushButton#ModeButton {{
    background: {t['bg_button']};
    color: {t['text_soft']};
    border: 1px solid {t['line_soft']};
    border-radius: 14px;
    min-height: 50px;
    font-size: 15px;
    font-weight: 700;
    outline: none;
}}

QPushButton#ModeButton:hover {{
    background: {t['bg_button_hover']};
    border: 1px solid {t['line_strong']};
}}

QPushButton#ModeButton[active="true"] {{
    background: {t['bg_panel_2']};
    color: {t['text_main']};
    border: 1px solid {t['line_focus']};
}}

QPushButton#ModeButton[active="false"] {{
    background: {t['bg_button']};
    color: {t['text_soft']};
    border: 1px solid {t['line_soft']};
}}

QPushButton#ModeButton[active="false"]:hover {{
    background: {t['bg_button_hover']};
    border: 1px solid {t['line_strong']};
}}

QPushButton#SubtleButton {{
    background: {t['bg_button']};
    color: {t['text_main']};
    border: 1px solid {t['line_soft']};
    border-radius: 16px;
    min-height: 50px;
    font-size: 15px;
    font-weight: 600;
    outline: none;
}}

QPushButton#SubtleButton:hover {{
    background: {t['bg_button_hover']};
    border: 1px solid {t['line_strong']};
}}

QPushButton#IconBtn {{
    background: {t['bg_input']};
    color: {t['text_main']};
    border: 1px solid {t['line_soft']};
    border-radius: 16px;
    font-size: 22px;
    font-weight: 400;
    outline: none;
}}

QPushButton#IconBtn:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_strong']};
}}

/* ============================================================================
   HEADER ICON BUTTONS
   ============================================================================ */

QPushButton#HeaderIconBtn {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 12px;
    outline: none;
    padding: 0px;
}}

QPushButton#HeaderIconBtn:hover {{
    background: {t['bg_panel_2']};
    border: 1px solid {t['line_strong']};
}}

QPushButton#HeaderIconBtn:pressed {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_focus']};
}}

QPushButton#HeaderIconBtn:disabled {{
    background: transparent;
    border: 1px solid transparent;
}}

QStackedWidget#ActionBtnStack {{
    background: transparent;
    border: none;
}}
QStackedWidget {{
    background: transparent;
}}

QPushButton#HeaderIconBtn[recording="true"] {{
    background: {t['danger']}22;
    border: 1px solid {t['danger']}88;
    border-radius: 12px;
}}

/* ============================================================================
   ADVANCED CARD
   ============================================================================ */

QFrame#AdvancedCard {{
    background: {t['bg_panel']};
    border: 1px solid {t['line_soft']};
    border-radius: 20px;
}}

/* ============================================================================
   STATUS LABELS
   ============================================================================ */

QLabel#StatusLabel {{
    color: {t['text_soft']};
    font-size: 14px;
    background: transparent;
}}

QLabel#StatusLabel[error="true"] {{
    color: {t['danger']};
}}

QLabel#StatusLabel[error="false"] {{
    color: {t['success']};
}}

/* ============================================================================
   LOADING SCREEN
   ============================================================================ */

QFrame#MainScreen {{
    background: {t['bg_main']};
}}

QFrame#LoadingCard {{
    background: {t['bg_card']};
    border: 1px solid {t['line_soft']};
    border-radius: 30px;
}}

QLabel#LoadingEyebrow {{
    color: {t['text_dim']};
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1.8px;
    background: transparent;
}}

QLabel#LoadingTitle {{
    color: {t['text_main']};
    font-size: 30px;
    font-weight: 700;
    background: transparent;
}}

QLabel#LoadingStatus {{
    color: {t['text_main']};
    font-size: 17px;
    font-weight: 600;
    background: transparent;
}}

QLabel#LoadingSubstatus {{
    color: {t['text_soft']};
    font-size: 14px;
    background: transparent;
}}

QFrame#LoadingProgressLine {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {t['accent_start']},
        stop:1 {t['accent_end']}
    );
    border: none;
    border-radius: 3px;
}}

QLabel#LoadingStageLabel {{
    color: {t['text_dim']};
    font-size: 13px;
    font-weight: 600;
    background: transparent;
}}

/* ============================================================================
   SIDEBAR & ALLIES
   ============================================================================ */

QFrame#MainScreenFrame {{
    background: transparent;
}}

QFrame#Sidebar {{
    background: {t['bg_sidebar']};
    border: none;
    border-right: 1px solid {t['line_soft']};
}}

QLabel#SectionHeader {{
    color: {t['text_dim']};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    background: transparent;
}}

QLineEdit#AllyInput {{
    background: {t['bg_input']};
    border: 1px solid {t['line_soft']};
    border-radius: 16px;
    padding-left: 18px;
    padding-right: 18px;
    color: {t['text_main']};
    font-size: 14px;
    min-height: 48px;
}}

QLineEdit#AllyInput:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_strong']};
}}

QLineEdit#AllyInput:focus {{
    border: 1px solid {t['line_focus']};
    background: {t['bg_input_focus']};
}}

QLabel#SearchStatusError {{
    color: {t['danger']};
    font-size: 13px;
    font-weight: 600;
    background: transparent;
}}

QListWidget#AlliesList {{
    background: transparent;
    border: none;
    outline: none;
}}

QListWidget#AlliesList::item {{
    background: transparent;
    border: none;
    border-radius: 16px;
    margin-bottom: 4px;
}}

QListWidget#AlliesList::item:hover {{
    background: {t['bg_input_hover']};
}}

QListWidget#AlliesList::item:selected {{
    background: {t['bg_panel_2']};
}}

QFrame#AllyCard {{
    background: transparent;
    border: none;
    border-radius: 12px;
}}

QFrame#AllyCard:hover {{
    background: {t['bg_input_hover']};
}}

QLabel#AllyAvatar {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']},
        stop:1 {t['accent_end']}
    );
    color: #ffffff;
    border-radius: 22px;
    font-size: 16px;
    font-weight: 700;
    border: 2px solid {t['accent_border']};
}}

QLabel#AllyName {{
    color: {t['text_main']};
    font-size: 14px;
    font-weight: 700;
    background: transparent;
}}

QLabel#AllyLastMessage {{
    color: {t['text_dim']};
    font-size: 12px;
    background: transparent;
}}

QLabel#AllyUnreadBadge {{
    background-color: {t['danger']};
    color: #ffffff;
    border-radius: 11px;
    font-size: 11px;
    font-weight: 800;
}}

/* ============================================================================
   CHAT AREA
   ============================================================================ */

QFrame#EmptyState {{
    background: transparent;
}}

QLabel#EmptyStateText {{
    color: {t['text_dim']};
    font-size: 15px;
    font-weight: 500;
    background: transparent;
}}

QFrame#ChatArea {{
    background: transparent;
    border: none;
}}

QFrame#ChatHeader {{
    background: {t['bg_topbar']};
    border: none;
    border-bottom: 1px solid {t['line_soft']};
}}

QLabel#ChatTitle {{
    color: {t['text_main']};
    font-size: 18px;
    font-weight: 700;
    background: transparent;
}}

/* ============================================================================
   MESSAGES AREA
   ============================================================================ */

QScrollArea#MessagesScroll {{
    background: transparent;
    border: none;
}}

QScrollArea#MessagesScroll > QWidget > QWidget {{
    background: transparent;
}}

/* Добавить явно: */
QScrollArea#MessagesScroll QScrollBar:vertical {{
    background: transparent;
    width: 5px;
    margin: 0;
}}

QScrollArea#MessagesScroll QScrollBar::handle:vertical {{
    background: {t['line_strong']};
    border-radius: 2px;
    min-height: 30px;
}}

QScrollArea#MessagesScroll QScrollBar::add-line:vertical,
QScrollArea#MessagesScroll QScrollBar::sub-line:vertical {{
    height: 0px;
    background: transparent;
}}

QScrollArea#MessagesScroll QScrollBar::add-page:vertical,
QScrollArea#MessagesScroll QScrollBar::sub-page:vertical {{
    background: transparent;
}}

/* ============================================================================
   MESSAGE BUBBLES
   ============================================================================ */

QFrame#MessageBubbleRow {{
    background: transparent;
    border: none;
}}

QFrame#BubbleOut {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['bg_bubble_out_start']},
        stop:1 {t['bg_bubble_out_end']}
    );
    border: 1px solid {t['line_strong']};
    border-radius: 16px;
    border-bottom-right-radius: 4px;
    max-width: 480px;
}}

QFrame#BubbleIn {{
    background: {t['bg_bubble_in']};
    border: 1px solid {t['line_soft']};
    border-radius: 16px;
    border-bottom-left-radius: 4px;
    max-width: 480px;
}}

QFrame#BubbleHighlight {{
    background: {t['accent']}18;
    border: 1px solid {t['accent']}55;
    border-radius: 16px;
    border-bottom-right-radius: 4px;
    max-width: 480px;
}}

QLabel#BubbleText {{
    color: {t['text_main']};
    font-size: 14px;
    line-height: 1.45;
    background: transparent;
    border: none;
}}

QLabel#BubbleTime {{
    color: {t['text_dim']};
    font-size: 11px;
    font-weight: 500;
    background: transparent;
    border: none;
}}

QLabel#BubbleStatus {{
    font-size: 12px;
    font-weight: 700;
    background: transparent;
    border: none;
}}

QLabel#BubbleStatus[read="true"] {{
    color: #4DA6FF;
}}

QLabel#BubbleStatus[read="false"] {{
    color: {t['text_dim']};
}}

/* ============================================================================
   INPUT AREA
   ============================================================================ */

QFrame#InputArea {{
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {t['bg_main']},
        stop:1 {t['bg_sidebar']}
    );
    border: none;
    border-top: 1px solid {t['line_soft']};
}}

QTextEdit#MessageInput {{
    background: {t['bg_input']};
    border: 1px solid {t['line_soft']};
    border-radius: 16px;
    padding: 4px 8px;
    color: {t['text_main']};
    font-size: 15px;
}}

QTextEdit#MessageInput:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_strong']};
}}

QTextEdit#MessageInput:focus {{
    border: 1px solid {t['line_focus']};
    background: {t['bg_input_focus']};
}}

/* ============================================================================
   SETTINGS SCREEN
   ============================================================================ */

QFrame#SettingsScreen {{
    background: {t['bg_main']};
}}

QFrame#SettingsHeader {{
    background: transparent;
    border-bottom: 1px solid {t['line_soft']};
}}

QLabel#SettingsMainTitle {{
    color: {t['text_main']};
    font-size: 22px;
    font-weight: 700;
    background: transparent;
}}

QTabWidget::pane {{
    border: none;
    background: transparent;
}}

QTabBar::tab {{
    background: transparent;
    color: {t['text_soft']};
    padding: 10px 20px;
    font-size: 14px;
    font-weight: 600;
    border-bottom: 2px solid transparent;
}}

QTabBar::tab:selected {{
    color: {t['text_main']};
    border-bottom: 2px solid {t['accent_start']};
}}

QTabBar::tab:hover {{
    color: {t['text_main']};
}}

QFrame#SettingsSection {{
    background: {t['bg_panel']};
    border: 1px solid {t['line_soft']};
    border-radius: 16px;
    padding: 20px;
}}

QLabel#SettingsSectionTitle {{
    color: {t['text_main']};
    font-size: 16px;
    font-weight: 700;
    background: transparent;
}}

QLabel#SettingsInfoLabel {{
    color: {t['text_soft']};
    font-size: 14px;
    background: transparent;
}}

QLabel#SettingsValueLabel {{
    color: {t['text_main']};
    font-size: 14px;
    font-weight: 600;
    background: transparent;
}}

QLabel#SettingsFingerprint {{
    color: {t['text_soft']};
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 13px;
    background: {t['bg_main']};
    border: 1px solid {t['line_strong']};
    border-radius: 8px;
    padding: 16px;
}}

QPushButton#SettingsActionBtn {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 12px;
    outline: none;
    color: {t['text_soft']};
    font-size: 14px;
    font-weight: 600;
    text-align: left;
    padding-left: 16px;
    min-height: 44px;
}}

QPushButton#SettingsActionBtn:hover {{
    background: {t['bg_panel_2']};
    border: 1px solid {t['line_strong']};
    color: {t['text_main']};
}}

QPushButton#SettingsActionBtn:pressed {{
    background: {t['bg_input_hover']};
}}

QPushButton#ThemeSelectBtn {{
    background: {t['bg_main']};
    color: {t['text_soft']};
    border: 1px solid {t['line_soft']};
    border-radius: 12px;
    font-size: 14px;
    font-weight: 600;
    text-align: left;
    padding-left: 20px;
    outline: none;
    min-height: 48px;
}}

QPushButton#ThemeSelectBtn:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_strong']};
}}

QPushButton#ThemeSelectBtn[active="true"] {{
    background: {t['selection_bg']};
    color: {t['text_main']};
    border: 1px solid {t['accent_start']};
    font-weight: 700;
}}

/* ============================================================================
   COMBOBOX
   ============================================================================ */

QComboBox {{
    background: {t['bg_input']};
    border: 1px solid {t['line_soft']};
    border-radius: 12px;
    padding: 12px 18px;
    color: {t['text_main']};
    font-size: 14px;
    font-weight: 500;
    outline: none;
}}

QComboBox:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_strong']};
}}

QComboBox::drop-down {{
    border: none;
    width: 30px;
}}

QComboBox::down-arrow {{
    image: none;
}}

QComboBox QAbstractItemView {{
    background: {t['bg_panel_2']};
    border: 1px solid {t['line_strong']};
    border-radius: 12px;
    outline: none;
    color: {t['text_main']};
    selection-background-color: {t['selection_bg']};
    selection-color: {t['text_main']};
    padding: 4px;
}}

QComboBox QAbstractItemView::item {{
    min-height: 36px;
    border-radius: 8px;
    padding-left: 12px;
}}

QComboBox QAbstractItemView::item:hover {{
    background: {t['bg_input_hover']};
}}

/* ============================================================================
   CALL UI
   ============================================================================ */

QFrame#CallWidget {{
    background: {t['bg_sidebar']};
    border: 1px solid {t['line_soft']};
    border-radius: 28px;
}}

QFrame#CallWidget:hover {{
    border: 1px solid {t['line_strong']};
}}

QFrame#CallWidgetAvatar {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']};
        stop:1 {t['accent_end']};
    );
    border-radius: 18px;
    min-width: 36px;
    max-width: 36px;
    min-height: 36px;
    max-height: 36px;
}}

QLabel#CallWidgetAvatarText {{
    color: #ffffff;
    background: transparent;
    border: none;
    font-size: 14px;
    font-weight: 700;
}}

QLabel#CallWidgetName {{
    color: {t['text_main']};
    font-size: 13px;
    font-weight: 600;
    background: transparent;
}}

QLabel#CallWidgetStatus {{
    color: {t['text_soft']};
    font-size: 12px;
    background: transparent;
    font-variant-numeric: tabular-nums;
}}

QPushButton#CallWidgetEndBtn {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 18px;
    outline: none;
}}

QPushButton#CallWidgetEndBtn:hover {{
    background: {t['danger']};
    border: 1px solid {t['danger']};
}}

QPushButton#CallWidgetExpandBtn {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 18px;
    outline: none;
}}

QPushButton#CallWidgetExpandBtn:hover {{
    background: {t['bg_button_hover']};
    border: 1px solid {t['line_strong']};
}}

QFrame#CallScreen {{
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {t['bg_main']};
        stop:0.5 {t['bg_panel']};
        stop:1 {t['bg_main']};
    );
}}

QFrame#CallScreenCenter {{
    background: transparent;
}}

QLabel#CallScreenAvatar {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']};
        stop:1 {t['accent_end']};
    );
    color: #ffffff;
    border-radius: 48px;
    font-size: 32px;
    font-weight: 700;
    border: 3px solid {t['accent_border']};
}}

QLabel#CallScreenName {{
    color: {t['text_main']};
    font-size: 22px;
    font-weight: 700;
    background: transparent;
}}

QLabel#CallScreenStatus {{
    color: {t['text_soft']};
    font-size: 15px;
    font-weight: 500;
    background: transparent;
    font-variant-numeric: tabular-nums;
}}

QFrame#CallControls {{
    background: {t['bg_sidebar']};
    border-top: 1px solid {t['line_soft']};
}}

QPushButton#CallControlBtn {{
    background: {t['bg_button']};
    border: 1px solid transparent;
    border-radius: 26px;
    outline: none;
}}

QPushButton#CallControlBtn:hover {{
    background: {t['bg_button_hover']};
    border: 1px solid {t['line_strong']};
}}

QPushButton#CallControlBtn:pressed {{
    background: {t['bg_input']};
    border: 1px solid {t['line_focus']};
}}

QPushButton#CallEndBtn {{
    background: {t['danger']};
    border: 1px solid {t['danger']};
    border-radius: 26px;
    outline: none;
}}

QPushButton#CallEndBtn:hover {{
    background: #e65c71;
    border: 1px solid #e65c71;
}}

QFrame#CallExpanded {{
    background: {t['bg_main']};
}}

QFrame#FloatingCallPill {{
    background: {t['bg_sidebar']};
    border: 1px solid {t['line_focus']};
    border-radius: 30px;
}}

QFrame#FloatingCallPill[screen_sharing="true"] {{
    border: 2px solid {t['screen_share_border']};
    background: {t['screen_share_bg']};
}}

QLabel#CallTimerText {{
    color: {t['text_main']};
    font-size: 14px;
    font-weight: 600;
    background: transparent;
    font-variant-numeric: tabular-nums;
}}

QLabel#CallDot {{
    font-size: 16px;
    background: transparent;
}}

/* ── Incoming Call Screen ── */

QFrame#IncomingCallScreen {{
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {t['bg_main']};
        stop:0.5 {t['bg_panel']};
        stop:1 {t['bg_main']};
    );
}}

QLabel#IncomingCallAvatar {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']};
        stop:1 {t['accent_end']};
    );
    color: #ffffff;
    border-radius: 48px;
    font-size: 32px;
    font-weight: 700;
    border: 3px solid {t['accent_border']};
}}

QLabel#IncomingCallTitle {{
    color: {t['text_soft']};
    font-size: 14px;
    font-weight: 500;
    background: transparent;
    letter-spacing: 1px;
}}

QLabel#IncomingCallName {{
    color: {t['text_main']};
    font-size: 22px;
    font-weight: 700;
    background: transparent;
}}

QPushButton#AcceptCallBtn {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {t['success']};
        stop:1 #2cb085;
    );
    color: #ffffff;
    border: none;
    border-radius: 25px;
    font-size: 15px;
    font-weight: 700;
    outline: none;
}}

QPushButton#AcceptCallBtn:hover {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #2cb085;
        stop:1 {t['success']};
    );
}}

QPushButton#RejectCallBtn {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {t['danger']};
        stop:1 #e65c71;
    );
    color: #ffffff;
    border: none;
    border-radius: 25px;
    font-size: 15px;
    font-weight: 700;
    outline: none;
}}

QPushButton#RejectCallBtn:hover {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #e65c71;
        stop:1 {t['danger']};
    );
}}

QPushButton#EndCallBtn {{
    background: transparent;
    border: 2px solid {t['danger']};
    border-radius: 20px;
    outline: none;
}}

QPushButton#EndCallBtn:hover {{
    background: {t['danger']};
}}

/* ── Old styles kept for compatibility ── */

QFrame#IncomingCallOverlay {{
    background: {t['bg_panel']};
    border: 1px solid {t['accent_start']};
    border-radius: 24px;
}}

QLabel#IncomingCallTitle {{
    color: {t['text_main']};
    font-size: 18px;
    font-weight: 700;
    background: transparent;
}}

QLabel#IncomingCallerName {{
    color: {t['text_dim']};
    font-size: 14px;
    font-weight: 600;
    background: transparent;
}}

QFrame#FloatingCallPill[screen_sharing="true"] {{
    border: 2px solid {t['screen_share_border']};
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {t['screen_share_bg']},
        stop:1 {t['bg_sidebar']}
    );
}}

QLabel#CallTimerText {{
    color: {t['text_main']};
    font-size: 14px;
    font-weight: 600;
    background: transparent;
    font-variant-numeric: tabular-nums;
}}

QLabel#CallDot {{
    font-size: 16px;
    background: transparent;
}}

QFrame#IncomingCallOverlay {{
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {t['bg_panel']},
        stop:1 {t['bg_panel_2']}
    );
    border: 1px solid {t['accent_start']};
    border-radius: 24px;
}}

QLabel#IncomingCallTitle {{
    color: {t['text_main']};
    font-size: 18px;
    font-weight: 700;
    background: transparent;
}}

QLabel#IncomingCallerName {{
    color: {t['text_dim']};
    font-size: 14px;
    font-weight: 600;
    background: transparent;
}}

QPushButton#AcceptCallBtn {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {t['success']},
        stop:1 #2cb085
    );
    color: #ffffff;
    border: none;
    border-radius: 14px;
    min-height: 44px;
    font-size: 14px;
    font-weight: 700;
    outline: none;
}}

QPushButton#AcceptCallBtn:hover {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #2cb085,
        stop:1 {t['success']}
    );
}}

QPushButton#RejectCallBtn {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {t['danger']},
        stop:1 #e65c71
    );
    color: #ffffff;
    border: none;
    border-radius: 14px;
    min-height: 44px;
    font-size: 14px;
    font-weight: 700;
    outline: none;
}}

QPushButton#RejectCallBtn:hover {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #e65c71,
        stop:1 {t['danger']}
    );
}}

QPushButton#EndCallBtn {{
    background: transparent;
    border: 2px solid {t['danger']};
    border-radius: 20px;
    outline: none;
}}

QPushButton#EndCallBtn:hover {{
    background: {t['danger']};
}}

/* ============================================================================
   VOLUME SLIDER
   ============================================================================ */

QSlider#VolumeSlider {{
    min-height: 20px;
    background: transparent;
}}

QSlider::groove:horizontal#VolumeSlider {{
    height: 4px;
    background: {t['line_strong']};
    border-radius: 2px;
}}

QSlider::sub-page:horizontal#VolumeSlider {{
    background: {t['accent_start']};
    border-radius: 2px;
}}

QSlider::handle:horizontal#VolumeSlider {{
    background: {t['text_main']};
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}}

QSlider::handle:horizontal:hover#VolumeSlider {{
    background: #ffffff;
}}

/* ============================================================================
   TYPING INDICATOR
   ============================================================================ */

QLabel#TypingIndicator {{
    color: {t['text_dim']};
    font-size: 12px;
    font-style: italic;
    font-weight: 500;
    background: transparent;
    border: none;
    padding-left: 4px;
}}

/* ============================================================================
   SCROLLBARS
   ============================================================================ */

QScrollBar:vertical {{
    background: transparent;
    width: 5px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {t['line_strong']};
    border-radius: 2px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background: {t['text_dim']};
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 5px;
}}

QScrollBar::handle:horizontal {{
    background: {t['line_strong']};
    border-radius: 2px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {t['text_dim']};
}}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* ============================================================================
   CONNECTION STATUS
   ============================================================================ */

QLabel#ConnectionStatus {{
    font-size: 11px;
    font-weight: 600;
    background: transparent;
    border: none;
    padding: 2px 8px;
}}

QLabel#ConnectionStatus[status="connected"] {{
    color: {t['success']};
}}

QLabel#ConnectionStatus[status="disconnected"] {{
    color: {t['danger']};
}}

QLabel#ConnectionStatus[status="reconnecting"] {{
    color: {t['warning']};
}}

/* ============================================================================
   IN-APP NOTIFICATION TOAST
   ============================================================================ */

QFrame#InAppNotification {{
    background: {t['bg_panel']};
    border: 1px solid {t['line_strong']};
    border-radius: 16px;
}}

QLabel#NotifAvatar {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']},
        stop:1 {t['accent_end']}
    );
    color: #ffffff;
    border-radius: 22px;
    font-size: 18px;
    font-weight: bold;
}}

QLabel#NotifTitle {{
    color: {t['text_main']};
    font-weight: 700;
    font-size: 13px;
    background: transparent;
}}

QLabel#NotifMessage {{
    color: {t['text_soft']};
    font-size: 12px;
    background: transparent;
}}

QPushButton#NotifCloseBtn {{
    background: transparent;
    color: {t['text_dim']};
    border: none;
    border-radius: 12px;
    font-size: 16px;
    font-weight: bold;
}}

QPushButton#NotifCloseBtn:hover {{
    background: {t['bg_input_hover']};
    color: {t['danger']};
}}

/* ============================================================================
   REPLY BLOCK (ЦИТАТА В СООБЩЕНИИ)
   ============================================================================ */

QFrame#ReplyBlock {{
    background: {t['bg_input']};
    border-left: 3px solid {t['accent_start']};
    border-radius: 4px;
    margin-bottom: 2px;
}}

QLabel#ReplySender {{
    color: {t['accent_start']};
    font-size: 11px;
    font-weight: 700;
    background: transparent;
}}

QLabel#ReplyText {{
    color: {t['text_soft']};
    font-size: 12px;
    background: transparent;
}}

/* ============================================================================
   REPLY PREVIEW (НАД ПОЛЕМ ВВОДА)
   ============================================================================ */

QFrame#ReplyPreview {{
    background: {t['bg_sidebar']};
    border-top: 1px solid {t['line_soft']};
    border-left: 3px solid {t['accent_start']};
}}

QLabel#ReplyPreviewSender {{
    color: {t['accent_start']};
    font-size: 12px;
    font-weight: 700;
    background: transparent;
}}

QLabel#ReplyPreviewText {{
    color: {t['text_soft']};
    font-size: 12px;
    background: transparent;
}}

QPushButton#ReplyCancelBtn {{
    background: transparent;
    color: {t['text_dim']};
    border: none;
    border-radius: 15px;
    font-size: 16px;
    font-weight: bold;
}}

QPushButton#ReplyCancelBtn:hover {{
    background: {t['bg_input_hover']};
    color: {t['danger']};
}}

/* ============================================================================
   SEARCH BAR
   ============================================================================ */

QFrame#SearchBar {{
    background: {t['bg_sidebar']};
    border-bottom: 1px solid {t['line_soft']};
}}

QLineEdit#SearchInput {{
    background: {t['bg_input']};
    border: 1px solid {t['line_soft']};
    border-radius: 12px;
    padding-left: 14px;
    padding-right: 14px;
    color: {t['text_main']};
    font-size: 13px;
    min-height: 32px;
}}

QLineEdit#SearchInput:focus {{
    border: 1px solid {t['line_focus']};
    background: {t['bg_input_focus']};
}}

QPushButton#SearchCloseBtn {{
    background: transparent;
    color: {t['text_dim']};
    border: none;
    border-radius: 15px;
    font-size: 14px;
    font-weight: bold;
}}

QPushButton#SearchCloseBtn:hover {{
    background: {t['bg_input_hover']};
    color: {t['danger']};
}}

QLabel#SearchEmptyLabel {{
    color: {t['text_dim']};
    font-size: 13px;
    font-style: italic;
    background: transparent;
    padding: 20px;
}}

/* ============================================================================
   VOICE PLAYER
   ============================================================================ */

QFrame#VoicePlayer {{
    background: transparent;
    min-width: 200px;
}}

QPushButton#VoicePlayBtn {{
    background: {t['bg_panel_2']};
    border: 1px solid {t['line_strong']};
    border-radius: 10px;
    outline: none;
    padding: 0px;
    min-width: 36px;
    max-width: 36px;
    min-height: 36px;
    max-height: 36px;
}}

QPushButton#VoicePlayBtn:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_focus']};
}}

QPushButton#VoicePlayBtn:pressed {{
    background: {t['bg_input']};
}}

QLabel#VoiceDuration {{
    color: {t['text_dim']};
    font-size: 11px;
    font-weight: 600;
    background: transparent;
    min-width: 32px;
}}

/* ============================================================================
   CONTEXT MENU
   ============================================================================ */

QMenu#BubbleContextMenu,
QMenu#ChatContextMenu {{
    background: {t['bg_panel']};
    border: 1px solid {t['line_strong']};
    border-radius: 12px;
    padding: 6px;
}}

QMenu#BubbleContextMenu::item,
QMenu#ChatContextMenu::item {{
    background: transparent;
    color: {t['text_main']};
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 13px;
}}

QMenu#BubbleContextMenu::item:selected,
QMenu#ChatContextMenu::item:selected {{
    background: {t['selection_bg']};
}}

QMenu#BubbleContextMenu::separator,
QMenu#ChatContextMenu::separator {{
    height: 1px;
    background: {t['line_soft']};
    margin: 4px 8px;
}}

/* ============================================================================
   IMAGE PREVIEW PANEL
   ============================================================================ */

QFrame#ImagePreviewPanel {{
    background: {t['bg_sidebar']};
    border: none;
    border-top: 1px solid {t['line_soft']};
}}

QLabel#ImagePreviewThumb {{
    background: transparent;
    border: none;
}}

QLineEdit#ImageCaptionInput {{
    background: {t['bg_input']};
    border: 1px solid {t['line_soft']};
    border-radius: 12px;
    padding-left: 14px;
    padding-right: 14px;
    color: {t['text_main']};
    font-size: 13px;
    min-height: 36px;
}}

QLineEdit#ImageCaptionInput:focus {{
    border: 1px solid {t['line_focus']};
    background: {t['bg_input_focus']};
}}

QPushButton#ImagePreviewSendBtn {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_start']},
        stop:1 {t['accent_end']}
    );
    color: {"#ffffff" if theme_name == "obsidian" else t['text_main']};
    border: 1px solid {t['accent_border']};
    border-radius: 10px;
    min-height: 36px;
    padding: 0px 18px;
    font-size: 13px;
    font-weight: 700;
    outline: none;
}}

QPushButton#ImagePreviewSendBtn:hover {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['accent_end']},
        stop:1 {t['accent_start']}
    );
}}

QPushButton#ImagePreviewCancelBtn {{
    background: transparent;
    color: {t['text_dim']};
    border: none;
    border-radius: 12px;
    font-size: 16px;
    font-weight: bold;
    outline: none;
    min-width: 32px;
    max-width: 32px;
    min-height: 32px;
    max-height: 32px;
}}

QPushButton#ImagePreviewCancelBtn:hover {{
    background: {t['bg_input_hover']};
    color: {t['danger']};
}}

/* ============================================================================
   VOICE RECORDING BAR
   ============================================================================ */

QFrame#VoiceRecordingBar {{
    background: {t['bg_sidebar']};
    border: none;
    border-top: 1px solid {t['line_soft']};
}}

QLabel#RecordingDot {{
    color: {t['danger']};
    font-size: 14px;
    font-weight: 700;
    background: transparent;
    border: none;
}}

QLabel#RecordingTimer {{
    color: {t['text_main']};
    font-size: 15px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    background: transparent;
    border: none;
    min-width: 40px;
}}

QLabel#RecordingLabel {{
    color: {t['text_dim']};
    font-size: 13px;
    font-style: italic;
    background: transparent;
    border: none;
}}

QPushButton#RecordCancelBtn {{
    background: transparent;
    color: {t['text_dim']};
    border: none;
    border-radius: 12px;
    font-size: 16px;
    font-weight: bold;
    outline: none;
    min-width: 36px;
    max-width: 36px;
    min-height: 36px;
    max-height: 36px;
}}

QPushButton#RecordCancelBtn:hover {{
    background: {t['bg_input_hover']};
    color: {t['danger']};
}}

/* ============================================================================
   IMAGE CAPTION LABEL (в bubble под картинкой)
   ============================================================================ */

QLabel#BubbleCaption {{
    color: {t['text_soft']};
    font-size: 13px;
    background: transparent;
    border: none;
}}

/* ============================================================================
   SIDEBAR TABS — СОЮЗНИКИ / ГРУППЫ
   ============================================================================ */

QPushButton#SidebarTabBtn {{
    background: transparent;
    border: 1px solid {t['line_soft']};
    border-radius: 8px;
    color: {t['text_dim']};
    font-size: 11px;
    font-weight: 600;
    padding: 5px 0px;
    letter-spacing: 0.5px;
    outline: none;
}}

QPushButton#SidebarTabBtn:checked {{
    background: {t['accent']};
    border-color: {t['accent']};
    color: #ffffff;
}}

QPushButton#SidebarTabBtn:hover:!checked {{
    border-color: {t['line_strong']};
    color: {t['text_soft']};
    background: {t['bg_panel_2']};
}}

/* ============================================================================
   CREATE GROUP BUTTON
   ============================================================================ */

QPushButton#CreateGroupBtn {{
    background: transparent;
    border: 1px solid {t['line_soft']};
    border-radius: 8px;
    color: {t['text_dim']};
    font-size: 11px;
    font-weight: 600;
    padding: 5px 10px;
    letter-spacing: 0.3px;
    outline: none;
    min-height: 30px;
}}

QPushButton#CreateGroupBtn:hover {{
    border-color: {t['accent']};
    color: {t['accent']};
    background: {t['bg_panel_2']};
}}

/* ============================================================================
   GROUP AVATAR
   ============================================================================ */

QLabel#GroupAvatar {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {t['bg_panel_2']},
        stop:1 {t['line_focus']}
    );
    color: {t['text_soft']};
    border-radius: 22px;
    font-size: 16px;
    font-weight: 700;
    border: 1px solid {t['line_strong']};
}}

/* ============================================================================
   SIDEBAR TAB FRAME
   ============================================================================ */

QFrame#SidebarTab {{
    background: transparent;
    border: none;
}}

/* ============================================================================
   CREATE GROUP PANEL
   ============================================================================ */

QFrame#CreateGroupPanel {{
    background: transparent;
    border: none;
}}


/* ============================================================================
   MESSAGES CONTAINER
   ============================================================================ */

QFrame#MessagesContainer {{
    background: transparent;
    border: none;
}}

/* ============================================================================
   CONN DOT BUTTON (SVG статус подключения)
   ============================================================================ */

QPushButton#ConnDotBtn {{
    background: transparent;
    border: none;
    outline: none;
    padding: 0px;
}}

QPushButton#ConnDotBtn:disabled {{
    background: transparent;
    border: none;
}}

/* ============================================================================
   CHAT HEADER ICON (SVG иконка слева от заголовка)
   ============================================================================ */

QLabel#ChatHeaderIcon {{
    background: transparent;
    border: none;
}}

/* ============================================================================
   REPLY BLOCK ICON
   ============================================================================ */

QLabel#ReplyBlockIcon {{
    background: transparent;
    border: none;
}}

/* ============================================================================
   CONTEXT MENU — ICON SIZE FIX
   ============================================================================ */

QMenu#BubbleContextMenu::item {{
    padding-left: 8px;
    padding-right: 14px;
}}

QMenu#BubbleContextMenu,
QMenu#ChatContextMenu {{
    background: {t['bg_panel']};
    border: 1px solid {t['line_strong']};
    border-radius: 12px;
    padding: 6px;
}}


/* ============================================================================
   SCREEN SHARING UI (добавлено для демонстрации экрана)
   ============================================================================ */

QPushButton#ScreenShareBtn {{
    background: transparent;
    border: 1px solid transparent;
    border-radius: 12px;
    outline: none;
}}

QPushButton#ScreenShareBtn:hover {{
    background: {t['bg_panel_2']};
    border: 1px solid {t['line_strong']};
}}

QPushButton#ScreenShareBtn[active="true"] {{
    background: {t['screen_share_bg']};
    border: 1px solid {t['screen_share_border']};
    color: {t['screen_share_active']};
}}

QLabel#ScreenShareIndicator {{
    color: {t['screen_share_active']};
    font-size: 11px;
    font-weight: 700;
    background: transparent;
    padding: 2px 8px;
    border-radius: 6px;
}}

QFrame#FloatingCallPill[screen_sharing="true"] {{
    border: 2px solid {t['screen_share_border']};
    background: {t['screen_share_bg']};
}}


/* ============================================================================
   SCREEN SHARE VIEWER
   ============================================================================ */

QWidget#ScreenShareViewer {{
    background: {t['bg_main']};
    border-radius: 8px;
}}

QLabel#ScreenShareFpsLabel {{
    color: {t['screen_share_active']};
    font-size: 11px;
    font-weight: 700;
    background: {t['bg_panel']};
    border: 1px solid {t['line_soft']};
    border-radius: 6px;
    padding: 2px 8px;
    font-variant-numeric: tabular-nums;
}}

QPushButton#ScreenShareCloseBtn {{
    background: {t['bg_button']};
    color: {t['text_soft']};
    border: 1px solid transparent;
    border-radius: 14px;
    font-size: 14px;
    font-weight: 700;
}}

QPushButton#ScreenShareCloseBtn:hover {{
    background: {t['bg_button_hover']};
    border: 1px solid {t['line_strong']};
    color: {t['danger']};
}}

QPushButton#ScreenShareMaxBtn {{
    background: {t['bg_button']};
    color: {t['text_soft']};
    border: 1px solid transparent;
    border-radius: 14px;
    font-size: 13px;
    font-weight: 600;
}}

QPushButton#ScreenShareMaxBtn:hover {{
    background: {t['bg_button_hover']};
    border: 1px solid {t['line_strong']};
    color: {t['text_main']};
}}

/* ============================================================================
   SCREEN SHARE IN CHAT
   ============================================================================ */

QFrame#ScreenShareContainer {{
    background: {t['bg_main']};
    border: 1px solid {t['line_soft']};
    border-radius: 12px;
    margin: 16px 32px;
}}

QLabel#ScreenShareVideo {{
    background: {t['bg_panel']};
    border: none;
}}

QLabel#ScreenShareLabel {{
    color: {t['text_dim']};
    font-size: 12px;
    background: transparent;
    padding: 8px;
}}

QPushButton#ScreenShareStopBtn {{
    background: {t['danger']};
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 6px 14px;
    font-size: 12px;
    font-weight: 600;
}}

QPushButton#ScreenShareStopBtn:hover {{
    background: #ff6b7d;
}}



/* ============================================================================
   SCREEN SHARE OVERLAY
   ============================================================================ */

QFrame#ScreenShareOverlay {{
    background: {t['bg_main']};
}}

QFrame#ScreenShareOverlayContainer {{
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 {t['bg_panel']},
        stop:1 {t['bg_panel_2']}
    );
    border: 1px solid {t['line_strong']};
    border-radius: 24px;
}}

QLabel#ScreenShareOverlayTitle {{
    color: {t['text_main']};
    font-size: 18px;
    font-weight: 700;
    background: transparent;
    letter-spacing: 1px;
}}

QFrame#MonitorPreviewCard {{
    background: {t['bg_panel_2']};
    border: 1px solid {t['line_strong']};
    border-radius: 16px;
}}

QFrame#MonitorPreviewCard:hover {{
    border: 1px solid {t['accent_border']};
    background: {t['bg_input_hover']};
}}

QLabel#MonitorPreviewImage {{
    background: {t['bg_panel']};
    border-radius: 8px;
}}

QLabel#MonitorPreviewName {{
    color: {t['text_main']};
    font-size: 13px;
    font-weight: 600;
    background: transparent;
}}

QLabel#MonitorPreviewRes {{
    color: {t['text_dim']};
    font-size: 11px;
    background: transparent;
}}

QPushButton#ScreenShareOverlayCancelBtn {{
    background: {t['bg_panel_2']};
    color: {t['text_soft']};
    border: 1px solid {t['line_strong']};
    border-radius: 12px;
    font-size: 14px;
    font-weight: 600;
}}

QPushButton#ScreenShareOverlayCancelBtn:hover {{
    background: {t['bg_input_hover']};
    border: 1px solid {t['line_focus']};
    color: {t['text_main']};
}}
"""


# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

APP_THEME = generate_qss("obsidian")