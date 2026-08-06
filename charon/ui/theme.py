"""Colour palette and stylesheet.

The palette carries meaning, not decoration: one accent for interactive things,
and a fixed traffic-light triple that is used *only* for security state.  Green
in Charon always means "encrypted and the server's identity is confirmed", amber
always means "encrypted but something is unproven", red always means "readable
by anyone on the wire".  Those three colours appear nowhere else, so the badge
in the status bar cannot be confused with ordinary UI chrome.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    name: str
    bg: str
    surface: str
    surface_alt: str
    border: str
    text: str
    text_muted: str
    accent: str
    accent_dim: str
    secure: str
    caution: str
    danger: str
    selection: str
    header: str


DARK = Palette(
    name="dark",
    bg="#0B1020",
    surface="#121A2E",
    surface_alt="#0F1626",
    border="#243356",
    text="#E6EDF7",
    text_muted="#8CA0C2",
    accent="#38BDF8",
    accent_dim="#1E4F6E",
    secure="#34D399",
    caution="#FBBF24",
    danger="#F87171",
    selection="#1B3556",
    header="#0D1424",
)

LIGHT = Palette(
    name="light",
    bg="#F3F6FC",
    surface="#FFFFFF",
    surface_alt="#EDF1F9",
    border="#CBD6E8",
    text="#12203B",
    text_muted="#5B6C89",
    accent="#0B72B5",
    accent_dim="#BBDDF2",
    secure="#0E8A5F",
    caution="#A96A05",
    danger="#C22E2E",
    selection="#D6E8F8",
    header="#E6EDF8",
)

PALETTES = {"dark": DARK, "light": LIGHT}


def palette(name: str) -> Palette:
    return PALETTES.get(name, DARK)


def stylesheet(p: Palette) -> str:
    from .icons import chevron_path

    chevron = chevron_path(p.text_muted)
    return f"""
    QWidget {{
        background: {p.bg};
        color: {p.text};
        font-size: 13px;
    }}
    QMainWindow, QDialog {{ background: {p.bg}; }}

    /* Labels inherit the window background otherwise, which makes every value
       inside a card look like a disabled input field. */
    QLabel, QCheckBox, QRadioButton {{ background: transparent; }}

    QLabel[role="title"] {{ font-size: 19px; font-weight: 600; }}
    QLabel[role="subtitle"] {{ color: {p.text_muted}; }}
    QLabel[role="section"] {{
        color: {p.text_muted}; font-size: 11px; font-weight: 700;
        letter-spacing: 1px;
    }}
    QLabel[role="mono"] {{
        font-family: "SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono", monospace;
        font-size: 12px;
    }}

    /* ---- panes ---- */
    QFrame[role="pane"] {{
        background: {p.surface};
        border: 1px solid {p.border};
        border-radius: 10px;
    }}
    QFrame[role="paneHeader"] {{
        background: {p.header};
        border: none;
        border-bottom: 1px solid {p.border};
        border-top-left-radius: 10px;
        border-top-right-radius: 10px;
    }}

    /* ---- lists ---- */
    QTreeWidget, QTableWidget, QListWidget {{
        background: {p.surface};
        alternate-background-color: {p.surface_alt};
        border: none;
        outline: none;
        selection-background-color: {p.selection};
        selection-color: {p.text};
    }}
    QTreeWidget::item, QTableWidget::item {{ padding: 4px 2px; border: none; }}
    QTreeWidget::item:selected, QTableWidget::item:selected {{
        background: {p.selection};
        color: {p.text};
    }}
    QHeaderView::section {{
        background: {p.header};
        color: {p.text_muted};
        border: none;
        border-bottom: 1px solid {p.border};
        padding: 6px 8px;
        font-size: 11px;
        font-weight: 600;
    }}

    /* ---- buttons ---- */
    QPushButton {{
        background: {p.surface_alt};
        border: 1px solid {p.border};
        border-radius: 7px;
        padding: 7px 14px;
        color: {p.text};
    }}
    QPushButton:hover {{ border-color: {p.accent}; }}
    QPushButton:pressed {{ background: {p.selection}; }}
    QPushButton:disabled {{ color: {p.text_muted}; border-color: {p.border}; }}
    QPushButton[role="primary"] {{
        background: {p.accent}; border: 1px solid {p.accent}; color: #08131F;
        font-weight: 600;
    }}
    QPushButton[role="primary"]:hover {{ background: {p.accent}; border-color: {p.text}; }}
    QPushButton[role="danger"] {{ color: {p.danger}; border-color: {p.danger}; }}
    QPushButton[role="ghost"] {{ background: transparent; border-color: transparent; }}
    QPushButton[role="ghost"]:hover {{ border-color: {p.border}; }}

    /* ---- inputs ---- */
    QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {{
        background: {p.surface_alt};
        border: 1px solid {p.border};
        border-radius: 7px;
        padding: 7px 9px;
        selection-background-color: {p.accent_dim};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {p.accent}; }}
    QLineEdit:disabled, QComboBox:disabled {{ color: {p.text_muted}; }}
    QComboBox::drop-down {{ border: none; width: 26px; subcontrol-position: right center; }}
    QComboBox::down-arrow {{ image: url("{chevron}"); width: 9px; height: 9px;
                             margin-right: 9px; }}
    QComboBox QAbstractItemView {{
        background: {p.surface};
        border: 1px solid {p.border};
        selection-background-color: {p.selection};
    }}

    QCheckBox, QRadioButton {{ spacing: 8px; }}
    QCheckBox::indicator, QRadioButton::indicator {{
        width: 16px; height: 16px;
        border: 1px solid {p.border};
        border-radius: 4px;
        background: {p.surface_alt};
    }}
    QRadioButton::indicator {{ border-radius: 8px; }}
    QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
        background: {p.accent}; border-color: {p.accent};
    }}
    QCheckBox::indicator:disabled {{ background: {p.bg}; }}

    /* ---- misc ---- */
    QToolBar {{ background: {p.header}; border: none; border-bottom: 1px solid {p.border};
                spacing: 4px; padding: 6px; }}
    QToolButton {{ background: transparent; border: 1px solid transparent;
                   border-radius: 7px; padding: 6px 10px; color: {p.text}; }}
    QToolButton:hover {{ background: {p.surface_alt}; border-color: {p.border}; }}
    QToolButton:disabled {{ color: {p.text_muted}; }}
    QStatusBar {{ background: {p.header}; border-top: 1px solid {p.border}; }}
    QStatusBar::item {{ border: none; }}
    QSplitter::handle {{ background: transparent; width: 8px; }}
    QProgressBar {{
        background: {p.surface_alt}; border: 1px solid {p.border};
        border-radius: 6px; height: 12px; text-align: center;
        color: {p.text_muted}; font-size: 10px;
    }}
    QProgressBar::chunk {{ background: {p.accent}; border-radius: 5px; }}
    QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 5px; min-height: 30px; }}
    QScrollBar::handle:vertical:hover {{ background: {p.accent_dim}; }}
    QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 5px; min-width: 30px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QTabWidget::pane {{ border: 1px solid {p.border}; border-radius: 8px; top: -1px; }}
    QTabBar::tab {{
        background: transparent; color: {p.text_muted};
        padding: 8px 16px; border: none; border-bottom: 2px solid transparent;
    }}
    QTabBar::tab:selected {{ color: {p.text}; border-bottom-color: {p.accent}; }}
    QMenu {{ background: {p.surface}; border: 1px solid {p.border}; padding: 6px; }}
    QMenu::item {{ padding: 6px 22px; border-radius: 5px; }}
    QMenu::item:selected {{ background: {p.selection}; }}
    QMenu::separator {{ height: 1px; background: {p.border}; margin: 5px 8px; }}
    QToolTip {{
        background: {p.surface}; color: {p.text};
        border: 1px solid {p.border}; padding: 6px;
    }}
    """
