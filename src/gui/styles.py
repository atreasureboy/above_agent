"""DriverScope GUI — Color scheme and ttk style configuration."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# Severity colors (matches src/report/html.py)
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}

SEVERITY_BG = {
    "critical": "#f8d7da",
    "high": "#ffe5cc",
    "medium": "#fff3cd",
    "low": "#d1ecf1",
    "info": "#e2e3e5",
}

# UI colors
BG_COLOR = "#f5f7fa"
CARD_BG = "#ffffff"
LOG_BG = "#1e1e1e"
LOG_FG = "#d4d4d4"
PRIMARY_BTN = "#0d6efd"
DANGER_BTN = "#dc3545"
SUCCESS_COLOR = "#28a745"
BORDER_COLOR = "#dee2e6"

# Fonts
FONT_UI = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 9, "bold")
FONT_MONO = ("Consolas", 9)
FONT_MONO_SMALL = ("Consolas", 8)
FONT_VALUE = ("Segoe UI", 22, "bold")
FONT_LABEL = ("Segoe UI", 8)


def apply_styles(root: tk.Tk) -> ttk.Style:
    """Configure ttk styles for the application."""
    style = ttk.Style()
    style.theme_use("vista")

    style.configure(".", font=FONT_UI, background=BG_COLOR)
    style.configure("TFrame", background=BG_COLOR)
    style.configure("TLabelframe", font=FONT_BOLD, background=BG_COLOR)
    style.configure("TLabelframe.Label", font=FONT_BOLD, foreground="#333")
    style.configure("TButton", font=FONT_UI, padding=4)
    style.configure("Primary.TButton", font=FONT_BOLD, foreground="#fff", background=PRIMARY_BTN)
    style.configure("Danger.TButton", font=FONT_BOLD, foreground="#fff", background=DANGER_BTN)
    style.configure("Success.TButton", font=FONT_BOLD, foreground="#fff", background=SUCCESS_COLOR)
    style.configure("TLabel", font=FONT_UI, background=BG_COLOR)
    style.configure("Value.TLabel", font=FONT_VALUE)
    style.configure("Label.TLabel", font=FONT_LABEL, foreground="#888")
    style.configure("TCheckbutton", font=FONT_UI, background=BG_COLOR)
    style.configure("Treeview", font=FONT_UI, rowheight=24)
    style.configure("Treeview.Heading", font=FONT_BOLD, background="#e9ecef")
    style.configure("TNotebook", background=BG_COLOR)
    style.configure("TNotebook.Tab", font=FONT_UI, padding=[12, 4])
    style.configure("TProgressbar", thickness=16)
    style.configure("Card.TFrame", background=CARD_BG)

    return style
