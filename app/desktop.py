"""Native Windows Desktop GUI Application for AI DAST Core (PyQt6 Edition).

Designed as a modern Cybersecurity Studio (Dark Obsidian & Neon Cyan theme) with:
- Sidebar navigation & multi-workspace layout
- Multi-Job Scan Queue & History (queue multiple scans, switch between jobs anytime)
- 1-Click Vulnerable Demo Target launcher
- Custom-painted Severity Donut Chart & KPI Cards
- Master-Detail Vulnerability Inspector (OWASP, CWE, Impact, Remediation, Raw Evidence)
- Interactive Attack Surface Tree (Asset Graph) & AI Intelligence (Facts/Hints)
- Burp-style HTTP Exchange History Table
- Color-coded Live Security Console
Runs 100% in-process as a standalone desktop app — zero web server, zero localhost.
"""

from __future__ import annotations

import html
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

load_dotenv(BASE_DIR / ".env")

from PyQt6.QtCore import QObject, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QFont,
    QIcon,
    QPainter,
    QPen,
    QPixmap,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
import webbrowser

from app.artex_web import BACKEND, ensure_artex_web_server, load_llm_pool, save_llm_pool
from app.models.scan import ScanConfig
from app.orchestrator.ai_analyst import analyze_scan_results, analyze_single_finding
from app.orchestrator.loop import ScanRunner
from app.orchestrator.planner import LlmPlanner, ScriptedPlanner
from app.policy.permissions import Capability, ConfirmationGate, PermissionSet
from app.policy.scope import build_scope_policy
from app.reports.json_report import build_report, render_markdown, write_report
from app.tools.catalog import build_default_registry


# --------------------------------------------------------------------------- #
# Theme Palette & Constants
# --------------------------------------------------------------------------- #

SEV_COLORS: dict[str, str] = {
    "CRITICAL": "#F43F5E",  # Rose Red
    "HIGH": "#F97316",      # Vibrant Orange
    "MEDIUM": "#EAB308",    # Amber Gold
    "LOW": "#38BDF8",       # Sky Blue
    "INFO": "#64748B",      # Slate Grey
}

SEV_BG_COLORS: dict[str, str] = {
    "CRITICAL": "#3B1219",
    "HIGH": "#3B1D0E",
    "MEDIUM": "#362B0B",
    "LOW": "#0E293B",
    "INFO": "#1E293B",
}

GLOBAL_QSS = """
QMainWindow {
    background-color: #090D16;
    color: #F1F5F9;
}
QWidget {
    font-family: 'Segoe UI', -apple-system, sans-serif;
    color: #E2E8F0;
}

/* Sidebar */
QFrame#Sidebar {
    background-color: #0D131F;
    border-right: 1px solid #1E293B;
}
QPushButton.NavBtn {
    background-color: transparent;
    color: #94A3B8;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 6px;
    padding: 9px 14px;
    text-align: left;
    font-size: 12.5px;
    font-weight: 600;
}
QPushButton.NavBtn:hover {
    background-color: #161F30;
    color: #F8FAFC;
}
QPushButton.NavBtn[active="true"] {
    background-color: #132238;
    color: #38BDF8;
    border-left: 3px solid #38BDF8;
}

/* Queue List in Sidebar */
QListWidget#QueueList {
    background-color: #090D16;
    border: 1px solid #1E293B;
    border-radius: 8px;
    outline: none;
    color: #E2E8F0;
    font-size: 11.5px;
}
QListWidget#QueueList::item {
    padding: 8px 10px;
    border-bottom: 1px solid #131C2E;
    border-radius: 4px;
}
QListWidget#QueueList::item:hover {
    background-color: #151E30;
}
QListWidget#QueueList::item:selected {
    background-color: #172A45;
    border-left: 3px solid #38BDF8;
    color: #FFFFFF;
}

/* Top Command Bar */
QFrame#TopBar {
    background-color: #0D131F;
    border-bottom: 1px solid #1E293B;
}
QFrame#AiConfigBar {
    background-color: #111927;
    border-bottom: 1px solid #1E293B;
}

/* Cards & Panels */
QFrame.Card {
    background-color: #111827;
    border: 1px solid #1E293B;
    border-radius: 10px;
}
QFrame.CardElevated {
    background-color: #151E30;
    border: 1px solid #26354D;
    border-radius: 10px;
}

/* Inputs */
QLineEdit {
    background-color: #090D16;
    border: 1px solid #26354D;
    border-radius: 7px;
    padding: 7px 12px;
    color: #F8FAFC;
    font-size: 13px;
    selection-background-color: #0284C7;
}
QLineEdit:focus {
    border: 1px solid #38BDF8;
    background-color: #0B111E;
}

QComboBox {
    background-color: #090D16;
    border: 1px solid #26354D;
    border-radius: 7px;
    padding: 6px 12px;
    color: #F8FAFC;
    font-size: 12px;
    font-weight: 600;
}
QComboBox:hover {
    border: 1px solid #38BDF8;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background-color: #111827;
    border: 1px solid #26354D;
    color: #F8FAFC;
    selection-background-color: #0284C7;
    outline: none;
}

/* Checkboxes */
QCheckBox {
    color: #CBD5E1;
    font-size: 12px;
    font-weight: 500;
    spacing: 7px;
}
QCheckBox::indicator {
    width: 17px;
    height: 17px;
    border-radius: 4px;
    border: 1px solid #334155;
    background-color: #090D16;
}
QCheckBox::indicator:hover {
    border: 1px solid #38BDF8;
}
QCheckBox::indicator:checked {
    background-color: #0284C7;
    border: 1px solid #38BDF8;
}

/* Action Buttons */
QPushButton#StartBtn {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284C7, stop:1 #2563EB);
    color: #FFFFFF;
    border: none;
    border-radius: 7px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: bold;
}
QPushButton#StartBtn:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369A1, stop:1 #1D4ED8);
}
QPushButton#StartBtn:disabled {
    background-color: #1E293B;
    color: #64748B;
}

QPushButton#DemoBtn {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10B981);
    color: #FFFFFF;
    border: none;
    border-radius: 7px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: bold;
}
QPushButton#DemoBtn:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669);
}

QPushButton#StopBtn {
    background-color: #BE123C;
    color: #FFFFFF;
    border: none;
    border-radius: 7px;
    padding: 8px 14px;
    font-size: 13px;
    font-weight: bold;
}
QPushButton#StopBtn:hover {
    background-color: #9F1239;
}
QPushButton#StopBtn:disabled {
    background-color: #1E293B;
    color: #475569;
}

QPushButton.SecondaryBtn {
    background-color: #1E293B;
    color: #E2E8F0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton.SecondaryBtn:hover {
    background-color: #334155;
    border: 1px solid #475569;
}

QPushButton.FilterPill {
    background-color: #161F30;
    color: #94A3B8;
    border: 1px solid #1E293B;
    border-radius: 13px;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: bold;
}
QPushButton.FilterPill:hover {
    background-color: #1E293B;
    color: #F8FAFC;
}
QPushButton.FilterPill[active="true"] {
    background-color: #0284C7;
    color: #FFFFFF;
    border: 1px solid #38BDF8;
}

/* Lists, Trees, Tables */
QListWidget, QTreeWidget, QTableWidget {
    background-color: #0D131F;
    border: 1px solid #1E293B;
    border-radius: 8px;
    outline: none;
    color: #E2E8F0;
    font-size: 12px;
}
QListWidget::item {
    padding: 10px 12px;
    border-bottom: 1px solid #161F30;
    border-radius: 4px;
}
QListWidget::item:hover {
    background-color: #151E30;
}
QListWidget::item:selected {
    background-color: #172A45;
    border-left: 3px solid #38BDF8;
    color: #FFFFFF;
}

QTreeWidget::item {
    padding: 6px 4px;
    border-bottom: 1px solid #131B2B;
}
QTreeWidget::item:hover {
    background-color: #151E30;
}
QTreeWidget::item:selected {
    background-color: #172A45;
    color: #38BDF8;
}

QHeaderView::section {
    background-color: #111827;
    color: #94A3B8;
    font-weight: bold;
    font-size: 11px;
    padding: 7px 10px;
    border: none;
    border-bottom: 1px solid #1E293B;
    border-right: 1px solid #161F30;
}

QTextBrowser, QTextEdit {
    background-color: #0B0F19;
    border: 1px solid #1E293B;
    border-radius: 8px;
    color: #E2E8F0;
    padding: 10px;
}

/* Progress Bar */
QProgressBar {
    background-color: #161F30;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #06B6D4, stop:1 #3B82F6);
    border-radius: 4px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #090D16;
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #26354D;
    min-height: 24px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #38BDF8;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background: #090D16;
    height: 8px;
    margin: 0px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #26354D;
    min-width: 24px;
    border-radius: 4px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""


# --------------------------------------------------------------------------- #
# Scan Job Model (Queue & History Item)
# --------------------------------------------------------------------------- #

@dataclass
class ScanJobItem:
    job_id: str
    target: str
    is_ai: bool
    planner_label: str
    allow_private: bool
    allow_active: bool
    allow_injection: bool
    api_key: str
    model: str
    base_url: str
    status: str = "queued"  # queued | running | completed | cancelled | failed
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    logs: list[str] = field(default_factory=list)
    step_count: int = 0
    step_text: str = "Đang chờ trong hàng đợi..."
    session: Any = None
    report: Any = None
    ai_analysis: dict[str, Any] = field(default_factory=dict)
    run_dir: str = ""
    error_msg: str = ""
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def display_label(self) -> str:
        short_url = self.target.replace("http://", "").replace("https://", "")
        if len(short_url) > 26:
            short_url = short_url[:24] + ".."
        if self.status == "queued":
            return f"⏳ [CHỜ] {self.job_id} · {self.planner_label}\n   🌐 {short_url}"
        if self.status == "running":
            return f"⚡ [ĐANG QUÉT] {self.job_id} · {self.planner_label}\n   🌐 {short_url}"
        if self.status == "completed":
            f_cnt = len(getattr(self.session, "findings", []) or []) if self.session else 0
            return f"✅ [{f_cnt} lỗi] {self.job_id} · {self.planner_label}\n   🌐 {short_url}"
        if self.status == "cancelled":
            return f"⏹ [ĐÃ HUỶ] {self.job_id} · {self.planner_label}\n   🌐 {short_url}"
        return f"❌ [LỖI] {self.job_id} · {self.planner_label}\n   🌐 {short_url}"


# --------------------------------------------------------------------------- #
# Custom Visual Widgets
# --------------------------------------------------------------------------- #

class StatCard(QFrame):
    """Modern KPI Metric Card with glowing top border and big counter."""

    def __init__(self, title: str, value: str, subtitle: str, accent_color: str) -> None:
        super().__init__()
        self.setProperty("class", "Card")
        self.setMinimumHeight(105)
        self._accent = QColor(accent_color)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 12)
        layout.setSpacing(4)

        self.title_lbl = QLabel(title.upper())
        self.title_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 700; letter-spacing: 0.5px;")
        layout.addWidget(self.title_lbl)

        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(f"color: {accent_color}; font-size: 28px; font-weight: 800;")
        layout.addWidget(self.value_lbl)

        self.sub_lbl = QLabel(subtitle)
        self.sub_lbl.setStyleSheet("color: #64748B; font-size: 11px;")
        layout.addWidget(self.sub_lbl)

    def set_metric(self, value: str, subtitle: str | None = None) -> None:
        self.value_lbl.setText(value)
        if subtitle is not None:
            self.sub_lbl.setText(subtitle)

    def paintEvent(self, event: Any) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self._accent, 3)
        painter.setPen(pen)
        painter.drawLine(12, 1, self.width() - 12, 1)


class SeverityDonutWidget(QWidget):
    """Custom-painted anti-aliased Donut Chart for vulnerability distribution."""

    def __init__(self) -> None:
        super().__init__()
        self.setMinimumSize(240, 210)
        self.counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

    def set_counts(self, counts: dict[str, int]) -> None:
        self.counts = dict(counts)
        self.update()

    def paintEvent(self, event: Any) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        size = min(w - 165, h - 24)
        size = max(110, min(size, 165))
        x = 14
        y = (h - size) // 2
        rect = QRectF(x, y, size, size)

        total = sum(self.counts.values())
        thickness = 18

        if total == 0:
            pen = QPen(QColor("#1E293B"), thickness)
            pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            painter.setPen(pen)
            painter.drawEllipse(rect.adjusted(thickness / 2, thickness / 2, -thickness / 2, -thickness / 2))
        else:
            start_angle = 90 * 16
            draw_rect = rect.adjusted(thickness / 2, thickness / 2, -thickness / 2, -thickness / 2)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                c = self.counts.get(sev, 0)
                if c <= 0:
                    continue
                span_angle = -int(round((c / total) * 360 * 16))
                if span_angle == 0:
                    span_angle = -16
                pen = QPen(QColor(SEV_COLORS[sev]), thickness)
                pen.setCapStyle(Qt.PenCapStyle.FlatCap)
                painter.setPen(pen)
                painter.drawArc(draw_rect, start_angle, span_angle)
                start_angle += span_angle

        # Center text
        painter.setPen(QColor("#F8FAFC"))
        font_big = QFont("Segoe UI", 20, QFont.Weight.Bold)
        painter.setFont(font_big)
        painter.drawText(rect.adjusted(0, -10, 0, -10), Qt.AlignmentFlag.AlignCenter, str(total))

        painter.setPen(QColor("#64748B"))
        font_sm = QFont("Segoe UI", 8, QFont.Weight.Bold)
        painter.setFont(font_sm)
        painter.drawText(rect.adjusted(0, 28, 0, 28), Qt.AlignmentFlag.AlignCenter, "LỖ HỔNG")

        # Right-side Legend
        leg_x = int(x + size + 22)
        leg_y = max(20, (h - 5 * 28) // 2)
        font_leg = QFont("Segoe UI", 9, QFont.Weight.DemiBold)
        painter.setFont(font_leg)

        for idx, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")):
            cy = leg_y + idx * 28
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(SEV_COLORS[sev]))
            painter.drawRoundedRect(leg_x, cy + 3, 10, 10, 3, 3)

            painter.setPen(QColor("#CBD5E1"))
            painter.drawText(leg_x + 16, cy + 12, f"{sev.title()}")

            painter.setPen(QColor(SEV_COLORS[sev]))
            val_str = str(self.counts.get(sev, 0))
            val_rect = QRectF(leg_x + 80, cy - 2, w - (leg_x + 96), 20)
            painter.drawText(val_rect, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, val_str)


# --------------------------------------------------------------------------- #
# Worker Signal Bridge
# --------------------------------------------------------------------------- #

class ScanSignals(QObject):
    job_started = pyqtSignal(str)
    job_log = pyqtSignal(str, str)
    job_progress = pyqtSignal(str, int, int, str)
    job_finished = pyqtSignal(str)
    job_failed = pyqtSignal(str, str)


# --------------------------------------------------------------------------- #
# Main Desktop Window
# --------------------------------------------------------------------------- #

class AiDastStudioWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("🛡️ AI DAST PRO — Enterprise Cybersecurity Desktop Suite")
        self.resize(1420, 870)
        self.setMinimumSize(1120, 720)
        self.setStyleSheet(GLOBAL_QSS)
        self.setWindowIcon(self._create_shield_icon())

        # Multi-Job Queue & History State
        self._jobs: dict[str, ScanJobItem] = {}
        self._job_order: list[str] = []  # newest first
        self._pending_queue: queue.Queue[str] = queue.Queue()
        self._selected_job_id: str | None = None
        self._running_job_id: str | None = None
        self._job_seq = 0

        self._all_findings: list[Any] = []
        self._active_sev_filter: str = "ALL"
        self._last_run_dir: Path = BASE_DIR / "runs"
        self._demo_server_url: str | None = None

        self.signals = ScanSignals()
        self.signals.job_started.connect(self._on_job_started)
        self.signals.job_log.connect(self._on_job_log)
        self.signals.job_progress.connect(self._on_job_progress)
        self.signals.job_finished.connect(self._on_job_finished)
        self.signals.job_failed.connect(self._on_job_failed)

        self._build_layout()
        self._load_past_runs_from_disk()

        # Start persistent background queue processor thread
        self._worker_thread = threading.Thread(target=self._queue_worker_loop, daemon=True)
        self._worker_thread.start()

    def _create_shield_icon(self) -> QIcon:
        pix = QPixmap(64, 64)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor("#0284C7"))
        p.setPen(QPen(QColor("#38BDF8"), 3))
        p.drawRoundedRect(6, 6, 52, 52, 14, 14)
        p.setPen(QColor("#FFFFFF"))
        p.setFont(QFont("Segoe UI", 22, QFont.Weight.Black))
        p.drawText(QRectF(0, 0, 64, 64), Qt.AlignmentFlag.AlignCenter, "🛡️")
        p.end()
        return QIcon(pix)

    # ----------------------------------------------------------------------- #
    # UI Construction
    # ----------------------------------------------------------------------- #

    def _build_layout(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Left Navigation + Scan Queue Sidebar
        self._build_sidebar(root_layout)

        # 2. Right Main Area (Top Command Bar + Stacked Pages + Status Footer)
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._build_top_command_bar(right_layout)
        self._build_ai_config_bar(right_layout)

        self.pages = QStackedWidget()
        right_layout.addWidget(self.pages, 1)

        self._build_page_dashboard()      # 0
        self._build_page_findings()       # 1
        self._build_page_assets()         # 2
        self._build_page_http_history()   # 3
        self._build_page_report()         # 4
        self._build_page_llm_pool()       # 5
        self._build_page_intercept()      # 6
        self._build_page_console()        # 7

        self._build_footer(right_layout)
        root_layout.addWidget(right_container, 1)

        self._switch_page(0)

    def _build_sidebar(self, parent_layout: QHBoxLayout) -> None:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(272)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(14, 14, 14, 12)
        sb_layout.setSpacing(4)

        # Brand Header
        brand_box = QHBoxLayout()
        logo_lbl = QLabel("🛡️")
        logo_lbl.setStyleSheet(
            "font-size: 24px; background: #132238; border: 1px solid #0284C7; border-radius: 8px; padding: 4px;"
        )
        logo_lbl.setFixedSize(40, 40)
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand_box.addWidget(logo_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        app_name = QLabel("AI DAST PRO · ENTERPRISE")
        app_name.setStyleSheet("color: #F8FAFC; font-size: 14px; font-weight: 800; letter-spacing: 0.5px;")
        app_ver = QLabel("AUTONOMOUS PENTEST SUITE v2.5")
        app_ver.setStyleSheet("color: #38BDF8; font-size: 8.5px; font-weight: 700; letter-spacing: 0.7px;")
        title_col.addWidget(app_name)
        title_col.addWidget(app_ver)
        brand_box.addLayout(title_col)
        brand_box.addStretch()
        sb_layout.addLayout(brand_box)

        sb_layout.addSpacing(6)

        nav_label_1 = QLabel("SCAN OPERATIONS")
        nav_label_1.setStyleSheet(
            "color: #475569; font-size: 9.5px; font-weight: 800; padding-left: 6px; letter-spacing: 0.7px;"
        )
        sb_layout.addWidget(nav_label_1)

        self.nav_buttons: list[QPushButton] = []
        nav_group_1 = [
            ("📊  Dashboard (Tổng quan)", 0),
            ("🔍  Findings & Retest (Lỗ hổng)", 1),
            ("⛓️  Exploration Chain & Map", 2),
            ("🌐  HTTP Traffic History", 3),
            ("📝  Executive Report (Báo cáo)", 4),
        ]
        for text, idx in nav_group_1:
            btn = QPushButton(text)
            btn.setProperty("class", "NavBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self._switch_page(i))
            sb_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sb_layout.addSpacing(4)
        nav_label_2 = QLabel("SYSTEM & AI INTELLIGENCE")
        nav_label_2.setStyleSheet(
            "color: #475569; font-size: 9.5px; font-weight: 800; padding-left: 6px; letter-spacing: 0.7px;"
        )
        sb_layout.addWidget(nav_label_2)

        nav_group_2 = [
            ("🧠  LLM Pool Manager (/system/llm)", 5),
            ("🛡️  Policy Intercept & Guardrails", 6),
            ("💻  Nhật ký (Live Console)", 7),
        ]
        for text, idx in nav_group_2:
            btn = QPushButton(text)
            btn.setProperty("class", "NavBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self._switch_page(i))
            sb_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sb_layout.addSpacing(6)

        # Scan Queue & History Section
        q_hdr_row = QHBoxLayout()
        self.queue_hdr_lbl = QLabel("📋 HÀNG ĐỢI & LỊCH SỬ (0)")
        self.queue_hdr_lbl.setStyleSheet(
            "color: #38BDF8; font-size: 10px; font-weight: 800; padding-left: 4px; letter-spacing: 0.6px;"
        )
        q_hdr_row.addWidget(self.queue_hdr_lbl)
        q_hdr_row.addStretch()
        sb_layout.addLayout(q_hdr_row)

        self.queue_list = QListWidget()
        self.queue_list.setObjectName("QueueList")
        self.queue_list.currentRowChanged.connect(self._on_queue_row_selected)
        sb_layout.addWidget(self.queue_list, 1)

        # Quick status card in sidebar bottom
        status_card = QFrame()
        status_card.setProperty("class", "Card")
        sc_layout = QVBoxLayout(status_card)
        sc_layout.setContentsMargins(12, 7, 12, 7)
        sc_layout.setSpacing(2)

        sc_hdr = QLabel("TRẠNG THÁI HÀNG ĐỢI")
        sc_hdr.setStyleSheet("color: #64748B; font-size: 9px; font-weight: 800;")
        self.sb_state_lbl = QLabel("🟢 Sẵn sàng nhận lệnh")
        self.sb_state_lbl.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 700;")
        sc_layout.addWidget(sc_hdr)
        sc_layout.addWidget(self.sb_state_lbl)
        sb_layout.addWidget(status_card)

        btn_row_sb = QHBoxLayout()
        btn_row_sb.setSpacing(6)
        artex_web_btn = QPushButton("🌐 Mở Web Console")
        artex_web_btn.setProperty("class", "SecondaryBtn")
        artex_web_btn.setStyleSheet(
            "background-color:#132238; color:#38BDF8; border:1px solid #0284C7; border-radius:6px; padding:6px 8px; font-size:11px; font-weight:700;"
        )
        artex_web_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        artex_web_btn.clicked.connect(self._open_artex_web_demo)
        btn_row_sb.addWidget(artex_web_btn)

        open_runs_btn = QPushButton("📂 Báo cáo")
        open_runs_btn.setProperty("class", "SecondaryBtn")
        open_runs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        open_runs_btn.clicked.connect(self._open_runs_folder)
        btn_row_sb.addWidget(open_runs_btn)
        sb_layout.addLayout(btn_row_sb)

        parent_layout.addWidget(sidebar)

    def _build_top_command_bar(self, parent_layout: QVBoxLayout) -> None:
        topbar = QFrame()
        topbar.setObjectName("TopBar")
        tb_layout = QVBoxLayout(topbar)
        tb_layout.setContentsMargins(18, 12, 18, 12)
        tb_layout.setSpacing(10)

        # Row 1: URL input + Planner Mode + Demo + Start/Queue + Stop/Cancel + ARTEX Web
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        target_badge = QLabel("🌐 MỤC TIÊU:")
        target_badge.setStyleSheet("color: #38BDF8; font-size: 12px; font-weight: 800;")
        row1.addWidget(target_badge)

        self.target_input = QLineEdit("http://testphp.vulnweb.com")
        self.target_input.setPlaceholderText(
            "Nhập URL mục tiêu (có thể bấm Quét nhiều lần liên tiếp để xếp vào Hàng đợi)"
        )
        self.target_input.setMinimumHeight(36)
        self.target_input.returnPressed.connect(self._enqueue_scan)
        row1.addWidget(self.target_input, 1)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "⚡ Scripted Recon Pro (Tốc độ cao)",
            "🤖 AI Master Planner (LLM Pool Failover)",
        ])
        self.mode_combo.setMinimumHeight(36)
        self.mode_combo.setFixedWidth(250)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        row1.addWidget(self.mode_combo)

        self.demo_btn = QPushButton("🚀  Chạy Demo")
        self.demo_btn.setObjectName("DemoBtn")
        self.demo_btn.setMinimumHeight(36)
        self.demo_btn.setToolTip("Bật mục tiêu mẫu có lỗ hổng (Demo Shop) và thêm ngay vào Hàng đợi quét")
        self.demo_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.demo_btn.clicked.connect(self._enqueue_demo_scan)
        row1.addWidget(self.demo_btn)

        self.start_btn = QPushButton("▶  QUÉT / +HÀNG ĐỢI")
        self.start_btn.setObjectName("StartBtn")
        self.start_btn.setMinimumHeight(36)
        self.start_btn.setToolTip("Bắt đầu quét ngay, hoặc thêm vào Hàng đợi nếu đang có lượt quét khác chạy")
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.clicked.connect(self._enqueue_scan)
        row1.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹  HUỶ JOB")
        self.stop_btn.setObjectName("StopBtn")
        self.stop_btn.setMinimumHeight(36)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setToolTip("Dừng lượt quét đang chạy hoặc huỷ Job đang chờ trong Hàng đợi")
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.clicked.connect(self._cancel_selected_or_running_job)
        row1.addWidget(self.stop_btn)

        self.top_artex_btn = QPushButton("🌐 Mở Web Console")
        self.top_artex_btn.setProperty("class", "SecondaryBtn")
        self.top_artex_btn.setMinimumHeight(36)
        self.top_artex_btn.setStyleSheet(
            "background-color:#132238; color:#38BDF8; border:1px solid #0284C7; border-radius:7px; padding:6px 12px; font-size:12px; font-weight:700;"
        )
        self.top_artex_btn.setToolTip("Mở giao diện Web Console (/system/llm, /tasks, Chuỗi suy luận) trên trình duyệt")
        self.top_artex_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.top_artex_btn.clicked.connect(self._open_artex_web_demo)
        row1.addWidget(self.top_artex_btn)

        tb_layout.addLayout(row1)

        # Row 2: Capability switches & quick presets
        row2 = QHBoxLayout()
        row2.setSpacing(18)

        cap_lbl = QLabel("Cấu hình quyền quét:")
        cap_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")
        row2.addWidget(cap_lbl)

        self.chk_active = QCheckBox("Active Scan (CORS, HTTP Methods, OpenAPI, Files)")
        self.chk_active.setChecked(True)
        row2.addWidget(self.chk_active)

        self.chk_injection = QCheckBox("Injection Probe (Kiểm thử SQLi / NoSQLi)")
        self.chk_injection.setChecked(True)
        row2.addWidget(self.chk_injection)

        self.chk_private = QCheckBox("Cho phép mạng nội bộ (Localhost / LAN IP)")
        self.chk_private.setChecked(True)
        row2.addWidget(self.chk_private)

        row2.addStretch()

        llm_pool_shortcut = QPushButton("🧠 Cấu hình LLM Pool & Ngắt mạch →")
        llm_pool_shortcut.setProperty("class", "SecondaryBtn")
        llm_pool_shortcut.setCursor(Qt.CursorShape.PointingHandCursor)
        llm_pool_shortcut.clicked.connect(lambda: self._switch_page(5))
        row2.addWidget(llm_pool_shortcut)

        tb_layout.addLayout(row2)

        parent_layout.addWidget(topbar)

    def _build_ai_config_bar(self, parent_layout: QVBoxLayout) -> None:
        self.ai_bar = QFrame()
        self.ai_bar.setObjectName("AiConfigBar")
        ai_layout = QHBoxLayout(self.ai_bar)
        ai_layout.setContentsMargins(18, 8, 18, 8)
        ai_layout.setSpacing(10)

        lbl_k = QLabel("🔑 AI API Key:")
        lbl_k.setStyleSheet("color: #38BDF8; font-size: 11px; font-weight: 700;")
        ai_layout.addWidget(lbl_k)

        self.ai_key_input = QLineEdit(os.environ.get("DAST_API_KEY", ""))
        self.ai_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.ai_key_input.setPlaceholderText("gsk_... hoặc sk-... (Lấy tự động từ .env nếu để trống)")
        self.ai_key_input.setFixedWidth(280)
        ai_layout.addWidget(self.ai_key_input)

        lbl_m = QLabel("🧠 Model Chính:")
        lbl_m.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 700;")
        ai_layout.addWidget(lbl_m)

        self.ai_model_input = QLineEdit(os.environ.get("DAST_MODEL", "llama-3.3-70b-versatile"))
        self.ai_model_input.setFixedWidth(210)
        ai_layout.addWidget(self.ai_model_input)

        lbl_b = QLabel("🔗 Base URL:")
        lbl_b.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 700;")
        ai_layout.addWidget(lbl_b)

        self.ai_base_input = QLineEdit(os.environ.get("DAST_BASE_URL", "https://api.groq.com/openai/v1"))
        ai_layout.addWidget(self.ai_base_input, 1)

        self.ai_bar.setVisible(False)
        parent_layout.addWidget(self.ai_bar)

    # ----------------------------------------------------------------------- #
    # Page 0: Dashboard
    # ----------------------------------------------------------------------- #

    def _build_page_dashboard(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(14)

        # 1. KPI Cards Row
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)

        self.card_total = StatCard("Tổng Lỗ Hổng", "0", "Chưa có lượt quét", "#38BDF8")
        self.card_crit_high = StatCard("Nguy Hiểm (Crit / High)", "0", "Mức ưu tiên xử lý ngay", "#F43F5E")
        self.card_endpoints = StatCard("Bề Mặt Tấn Công", "0", "Endpoints & Đường dẫn", "#A855F7")
        self.card_requests = StatCard("Tốc Độ & Truy Vấn", "0 reqs", "Thời gian: 0.0s", "#10B981")

        kpi_row.addWidget(self.card_total)
        kpi_row.addWidget(self.card_crit_high)
        kpi_row.addWidget(self.card_endpoints)
        kpi_row.addWidget(self.card_requests)
        layout.addLayout(kpi_row)

        # 2. Middle Row: Donut Chart + Top Findings Preview
        mid_row = QHBoxLayout()
        mid_row.setSpacing(14)

        chart_card = QFrame()
        chart_card.setProperty("class", "Card")
        chart_card.setFixedWidth(360)
        cc_layout = QVBoxLayout(chart_card)
        cc_layout.setContentsMargins(16, 14, 16, 14)

        cc_title = QLabel("📊 PHÂN BỔ MỨC ĐỘ NGUY HIỂM")
        cc_title.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 800; letter-spacing: 0.5px;")
        cc_layout.addWidget(cc_title)

        self.donut_chart = SeverityDonutWidget()
        cc_layout.addWidget(self.donut_chart, 1)
        mid_row.addWidget(chart_card)

        preview_card = QFrame()
        preview_card.setProperty("class", "Card")
        pv_layout = QVBoxLayout(preview_card)
        pv_layout.setContentsMargins(16, 14, 16, 14)
        pv_layout.setSpacing(8)

        pv_header = QHBoxLayout()
        self.pv_title_lbl = QLabel("🔥 PHÁT HIỆN NỔI BẬT & AI PHÂN TÍCH KẾT QUẢ")
        self.pv_title_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 800; letter-spacing: 0.5px;")
        pv_header.addWidget(self.pv_title_lbl)
        pv_header.addStretch()

        self.ai_analyze_job_btn = QPushButton("🤖 AI Phân Tích Kết Quả (LLM Pool)")
        self.ai_analyze_job_btn.setProperty("class", "SecondaryBtn")
        self.ai_analyze_job_btn.setStyleSheet(
            "background-color:#4C1D95; color:#F5F3FF; border:1px solid #A855F7; border-radius:6px; padding:5px 12px; font-size:11.5px; font-weight:800;"
        )
        self.ai_analyze_job_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_analyze_job_btn.clicked.connect(self._run_ai_analysis_for_current_job)
        pv_header.addWidget(self.ai_analyze_job_btn)

        chain_btn = QPushButton("⛓️ Xem Chuỗi Suy Luận →")
        chain_btn.setProperty("class", "SecondaryBtn")
        chain_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        chain_btn.clicked.connect(lambda: self._switch_page(2))
        pv_header.addWidget(chain_btn)

        view_all_btn = QPushButton("Xem chi tiết lỗ hổng →")
        view_all_btn.setProperty("class", "SecondaryBtn")
        view_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        view_all_btn.clicked.connect(lambda: self._switch_page(1))
        pv_header.addWidget(view_all_btn)
        pv_layout.addLayout(pv_header)

        self.dash_summary_browser = QTextBrowser()
        self.dash_summary_browser.setOpenExternalLinks(False)
        self.dash_summary_browser.setHtml(self._render_welcome_dashboard_html())
        pv_layout.addWidget(self.dash_summary_browser, 1)

        mid_row.addWidget(preview_card, 1)
        layout.addLayout(mid_row, 1)

        # 3. Bottom Live Activity Feed (Mini Console)
        feed_card = QFrame()
        feed_card.setProperty("class", "Card")
        feed_card.setFixedHeight(165)
        fd_layout = QVBoxLayout(feed_card)
        fd_layout.setContentsMargins(14, 10, 14, 10)
        fd_layout.setSpacing(6)

        fd_hdr = QHBoxLayout()
        fd_title = QLabel("⚡ TIẾN TRÌNH THỰC THI TRỰC TIẾP (LIVE EXECUTION STREAM)")
        fd_title.setStyleSheet("color: #38BDF8; font-size: 11px; font-weight: 800;")
        fd_hdr.addWidget(fd_title)
        fd_hdr.addStretch()
        self.step_badge_lbl = QLabel("Chờ lệnh khởi chạy")
        self.step_badge_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 600;")
        fd_hdr.addWidget(self.step_badge_lbl)
        fd_layout.addLayout(fd_hdr)

        self.mini_log = QTextEdit()
        self.mini_log.setReadOnly(True)
        self.mini_log.setStyleSheet(
            "font-family: 'Consolas', monospace; font-size: 11px; background-color: #070A12; "
            "border: 1px solid #161F30; padding: 6px;"
        )
        fd_layout.addWidget(self.mini_log, 1)

        layout.addWidget(feed_card)
        self.pages.addWidget(page)

    # ----------------------------------------------------------------------- #
    # Page 1: Master-Detail Findings Inspector + 1-Click Retest & Traffic Link
    # ----------------------------------------------------------------------- #

    def _build_page_findings(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(8)

        self.search_finding_input = QLineEdit()
        self.search_finding_input.setPlaceholderText("🔎 Tìm kiếm lỗ hổng theo tên, URL, OWASP, CWE...")
        self.search_finding_input.setFixedWidth(260)
        self.search_finding_input.textChanged.connect(self._apply_findings_filter)
        filter_bar.addWidget(self.search_finding_input)

        self.filter_pills: dict[str, QPushButton] = {}
        for sev_key, label in [
            ("ALL", "Tất cả (0)"),
            ("CRITICAL", "🔴 Critical (0)"),
            ("HIGH", "🟠 High (0)"),
            ("MEDIUM", "🟡 Medium (0)"),
            ("LOW", "🔵 Low (0)"),
            ("INFO", "⚪ Info (0)"),
        ]:
            pill = QPushButton(label)
            pill.setProperty("class", "FilterPill")
            pill.setProperty("active", "true" if sev_key == "ALL" else "false")
            pill.setCursor(Qt.CursorShape.PointingHandCursor)
            pill.clicked.connect(lambda checked, k=sev_key: self._set_sev_filter(k))
            filter_bar.addWidget(pill)
            self.filter_pills[sev_key] = pill

        filter_bar.addStretch()

        # AI Deep Analysis & Remediation Code Button + 1-Click Retest
        self.ai_finding_btn = QPushButton("🤖 AI Phân Tích & Code Vá Lỗi")
        self.ai_finding_btn.setProperty("class", "SecondaryBtn")
        self.ai_finding_btn.setStyleSheet(
            "background-color:#4C1D95; color:#F5F3FF; border:1px solid #A855F7; border-radius:6px; padding:6px 12px; font-size:12px; font-weight:700;"
        )
        self.ai_finding_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ai_finding_btn.clicked.connect(self._ai_analyze_selected_finding)
        filter_bar.addWidget(self.ai_finding_btn)

        self.retest_btn = QPushButton("🔄 Kiểm tra lại (Live Retest)")
        self.retest_btn.setProperty("class", "SecondaryBtn")
        self.retest_btn.setStyleSheet(
            "background-color:#065F46; color:#ECFDF5; border:1px solid #10B981; border-radius:6px; padding:6px 12px; font-size:12px; font-weight:700;"
        )
        self.retest_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.retest_btn.clicked.connect(self._retest_selected_finding)
        filter_bar.addWidget(self.retest_btn)

        self.jump_traffic_btn = QPushButton("🌐 Xem Gói Tin HTTP Bằng Chứng")
        self.jump_traffic_btn.setProperty("class", "SecondaryBtn")
        self.jump_traffic_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.jump_traffic_btn.clicked.connect(self._jump_to_finding_traffic)
        filter_bar.addWidget(self.jump_traffic_btn)

        layout.addLayout(filter_bar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(8)

        self.findings_list = QListWidget()
        self.findings_list.currentRowChanged.connect(self._on_finding_selected)
        splitter.addWidget(self.findings_list)

        self.finding_inspector = QTextBrowser()
        self.finding_inspector.setOpenExternalLinks(True)
        self.finding_inspector.setHtml(
            "<div style='color:#64748B; text-align:center; margin-top:80px; font-size:14px;'>"
            "Chọn một lỗ hổng ở danh sách bên trái để xem phân tích chuyên sâu,<br>"
            "bằng chứng kỹ thuật (Evidence), mã CWE/OWASP, hoặc nhấn <b>🔄 Kiểm tra lại (Retest)</b>.</div>"
        )
        splitter.addWidget(self.finding_inspector)

        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        layout.addWidget(splitter, 1)

        self.pages.addWidget(page)

    # ----------------------------------------------------------------------- #
    # Page 2: Exploration Chain & Asset Graph
    # ----------------------------------------------------------------------- #

    def _build_page_assets(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        hdr = QHBoxLayout()
        title = QLabel("⛓️ AI EXPLORATION & ATTACK CHAIN (BẢN ĐỒ BỀ MẶT & CHUỖI SUY LUẬN)")
        title.setStyleSheet("color: #38BDF8; font-size: 12px; font-weight: 800;")
        hdr.addWidget(title)
        hdr.addStretch()

        expand_btn = QPushButton("Mở rộng toàn bộ cây")
        expand_btn.setProperty("class", "SecondaryBtn")
        expand_btn.clicked.connect(lambda: self.asset_tree.expandAll())
        hdr.addWidget(expand_btn)
        layout.addLayout(hdr)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(8)

        self.asset_tree = QTreeWidget()
        self.asset_tree.setHeaderLabels(["Thành phần / Endpoint", "Trạng thái", "Công cụ đã kiểm tra / Lỗ hổng"])
        self.asset_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.asset_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.asset_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        splitter.addWidget(self.asset_tree)

        self.intel_browser = QTextBrowser()
        self.intel_browser.setHtml(
            "<div style='color:#64748B; text-align:center; margin-top:80px; font-size:13px;'>"
            "Đồ thị Chuỗi Suy Luận AI (Khởi điểm → Ý định → Công cụ → Dữ kiện → Lỗ hổng → Gợi ý) sẽ hiển thị tại đây.</div>"
        )
        splitter.addWidget(self.intel_browser)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter, 1)

        self.pages.addWidget(page)

    # ----------------------------------------------------------------------- #
    # Page 3: HTTP Traffic History with Advanced Filter Bar
    # ----------------------------------------------------------------------- #

    def _build_page_http_history(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        top_bar = QHBoxLayout()
        top_bar.setSpacing(10)

        hdr = QLabel("🌐 LƯU LƯỢNG HTTP (TRAFFIC AUDIT)")
        hdr.setStyleSheet("color: #38BDF8; font-size: 12px; font-weight: 800;")
        top_bar.addWidget(hdr)

        self.http_method_combo = QComboBox()
        self.http_method_combo.addItems(["Tất cả Method", "GET", "POST", "OPTIONS", "HEAD", "TRACE"])
        self.http_method_combo.currentIndexChanged.connect(self._apply_http_filter)
        top_bar.addWidget(self.http_method_combo)

        self.http_status_combo = QComboBox()
        self.http_status_combo.addItems(["Tất cả Status", "2xx Thành công", "3xx Chuyển hướng", "4xx Lỗi Client", "5xx Lỗi Server"])
        self.http_status_combo.currentIndexChanged.connect(self._apply_http_filter)
        top_bar.addWidget(self.http_status_combo)

        self.http_search_input = QLineEdit()
        self.http_search_input.setPlaceholderText("🔎 Lọc gói tin theo URL hoặc Content-Type...")
        self.http_search_input.textChanged.connect(self._apply_http_filter)
        top_bar.addWidget(self.http_search_input, 1)

        clear_flt_btn = QPushButton("Xoá lọc")
        clear_flt_btn.setProperty("class", "SecondaryBtn")
        clear_flt_btn.clicked.connect(self._reset_http_filter)
        top_bar.addWidget(clear_flt_btn)

        self.http_count_lbl = QLabel("0 gói tin")
        self.http_count_lbl.setStyleSheet("color: #94A3B8; font-size: 11.5px; font-weight: 700;")
        top_bar.addWidget(self.http_count_lbl)

        layout.addLayout(top_bar)

        self.http_table = QTableWidget(0, 7)
        self.http_table.setHorizontalHeaderLabels([
            "#", "Method", "Status", "URL Yêu Cầu", "Content-Type", "Kích thước", "Thời gian (ms)"
        ])
        self.http_table.verticalHeader().setVisible(False)
        self.http_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.http_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.http_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.http_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.http_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.http_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.http_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.http_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.http_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.http_table, 1)

        self.pages.addWidget(page)

    # ----------------------------------------------------------------------- #
    # Page 4: Executive Markdown Report
    # ----------------------------------------------------------------------- #

    def _build_page_report(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        hdr_row = QHBoxLayout()
        title = QLabel("📝 EXECUTIVE MARKDOWN REPORT (BÁO CÁO KIỂM THỬ XÂM NHẬP)")
        title.setStyleSheet("color: #38BDF8; font-size: 12px; font-weight: 800;")
        hdr_row.addWidget(title)
        hdr_row.addStretch()

        copy_md_btn = QPushButton("📋 Sao chép toàn bộ Markdown vào Clipboard")
        copy_md_btn.setProperty("class", "SecondaryBtn")
        copy_md_btn.setStyleSheet(
            "background-color:#0284C7; color:#FFFFFF; border:1px solid #38BDF8; border-radius:6px; padding:6px 14px; font-weight:700;"
        )
        copy_md_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_md_btn.clicked.connect(self._copy_markdown_report)
        hdr_row.addWidget(copy_md_btn)

        open_dir_btn = QPushButton("📂 Mở thư mục chứa report.md / report.json")
        open_dir_btn.setProperty("class", "SecondaryBtn")
        open_dir_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        open_dir_btn.clicked.connect(self._open_runs_folder)
        hdr_row.addWidget(open_dir_btn)

        layout.addLayout(hdr_row)

        self.report_md_edit = QTextEdit()
        self.report_md_edit.setReadOnly(True)
        self.report_md_edit.setStyleSheet(
            "font-family: 'Consolas', 'Segoe UI', monospace; font-size: 12.5px; "
            "background-color: #080C15; border: 1px solid #1E293B; padding: 14px; color: #E2E8F0;"
        )
        self.report_md_edit.setPlainText("Chọn một chiến dịch đã hoàn tất để xem Báo cáo Markdown chi tiết.")
        layout.addWidget(self.report_md_edit, 1)

        self.pages.addWidget(page)

    # ----------------------------------------------------------------------- #
    # Page 5: LLM Pool Management (/system/llm/) & Call Telemetry
    # ----------------------------------------------------------------------- #

    def _build_page_llm_pool(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        hdr_row = QHBoxLayout()
        hdr_row.setSpacing(8)
        title = QLabel("🧠 QUẢN LÝ CỤM MÔ HÌNH AI & NGẮT MẠCH TỰ ĐỘNG (/system/llm/)")
        title.setStyleSheet("color: #38BDF8; font-size: 12px; font-weight: 800;")
        hdr_row.addWidget(title)
        hdr_row.addStretch()

        self.rr_toggle_btn = QPushButton("🔁 Luân chuyển tự động (Round-Robin): BẬT")
        self.rr_toggle_btn.setProperty("class", "SecondaryBtn")
        self.rr_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.rr_toggle_btn.clicked.connect(self._toggle_llm_round_robin)
        hdr_row.addWidget(self.rr_toggle_btn)

        sim_fail_btn = QPushButton("⚡ Giả lập Quá tải & Tự động Failover")
        sim_fail_btn.setProperty("class", "SecondaryBtn")
        sim_fail_btn.setStyleSheet(
            "background-color:#881337; color:#FFE4E6; border:1px solid #F43F5E; border-radius:6px; padding:6px 12px; font-weight:700;"
        )
        sim_fail_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        sim_fail_btn.clicked.connect(self._simulate_llm_failover)
        hdr_row.addWidget(sim_fail_btn)

        recover_all_btn = QPushButton("♻️ Khôi phục Toàn bộ Mạch")
        recover_all_btn.setProperty("class", "SecondaryBtn")
        recover_all_btn.setStyleSheet(
            "background-color:#065F46; color:#ECFDF5; border:1px solid #10B981; border-radius:6px; padding:6px 12px; font-weight:700;"
        )
        recover_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        recover_all_btn.clicked.connect(self._recover_all_llm_models)
        hdr_row.addWidget(recover_all_btn)

        promote_btn = QPushButton("⭐ Đặt dòng chọn làm Model Chính")
        promote_btn.setProperty("class", "SecondaryBtn")
        promote_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        promote_btn.clicked.connect(self._promote_selected_llm_model)
        hdr_row.addWidget(promote_btn)

        layout.addLayout(hdr_row)

        self.llm_table = QTableWidget(0, 8)
        self.llm_table.setHorizontalHeaderLabels([
            "Vai trò", "Tên Mô Hình", "Nhà cung cấp", "Model ID", "Ưu tiên", "Giới hạn (RPS/RPM)", "Độ trễ / Tỉ lệ", "Trạng thái Mạch (Circuit Breaker)"
        ])
        self.llm_table.verticalHeader().setVisible(False)
        self.llm_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.llm_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.llm_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.llm_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.llm_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.llm_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.llm_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.llm_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.llm_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.llm_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.llm_table.setMaximumHeight(225)
        layout.addWidget(self.llm_table)

        self.llm_cards_browser = QTextBrowser()
        self.llm_cards_browser.setOpenExternalLinks(False)
        layout.addWidget(self.llm_cards_browser, 1)

        self.pages.addWidget(page)
        self._refresh_llm_pool_ui()

    # ----------------------------------------------------------------------- #
    # Page 6: Policy Interception, Guardrails & Multi-Agent/Skill Catalog
    # ----------------------------------------------------------------------- #

    def _build_page_intercept(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        hdr = QLabel("🛡️ QUY TẮC CHẶN CHÍNH SÁCH (INTERCEPT RULES), LỊCH SỬ PHÊ DUYỆT & ĐA TÁC TỬ (AGENTS / SKILLS)")
        hdr.setStyleSheet("color: #38BDF8; font-size: 12px; font-weight: 800;")
        layout.addWidget(hdr)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(8)

        self.intercept_browser = QTextBrowser()
        self.intercept_browser.setHtml(self._render_intercept_overview_html())
        splitter.addWidget(self.intercept_browser)

        self.approval_table = QTableWidget(0, 6)
        self.approval_table.setHorizontalHeaderLabels([
            "Bước", "Công cụ (Tool)", "Mục tiêu (Target / Page)", "Chốt chặn (Guardrail Rule)", "Quyết định", "Chi tiết Chính sách"
        ])
        self.approval_table.verticalHeader().setVisible(False)
        self.approval_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.approval_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.approval_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.approval_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.approval_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.approval_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.approval_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.approval_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        splitter.addWidget(self.approval_table)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter, 1)

        self.pages.addWidget(page)

    # ----------------------------------------------------------------------- #
    # Page 7: Live Security Console
    # ----------------------------------------------------------------------- #

    def _build_page_console(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        title = QLabel("💻 NHẬT KÝ HỆ THỐNG TRỰC TIẾP (LIVE SECURITY CONSOLE)")
        title.setStyleSheet("color: #38BDF8; font-size: 12px; font-weight: 800;")
        top_row.addWidget(title)
        top_row.addStretch()

        clear_btn = QPushButton("🗑️ Xóa nhật ký hiển thị")
        clear_btn.setProperty("class", "SecondaryBtn")
        clear_btn.clicked.connect(lambda: self.console_edit.clear())
        top_row.addWidget(clear_btn)
        layout.addLayout(top_row)

        self.console_edit = QTextEdit()
        self.console_edit.setReadOnly(True)
        self.console_edit.setStyleSheet(
            "font-family: 'Consolas', 'Cascadia Mono', monospace; font-size: 12px; "
            "background-color: #060911; border: 1px solid #1E293B; padding: 12px;"
        )
        layout.addWidget(self.console_edit, 1)

        self.pages.addWidget(page)

    # ----------------------------------------------------------------------- #
    # Footer Status Bar
    # ----------------------------------------------------------------------- #

    def _build_footer(self, parent_layout: QVBoxLayout) -> None:
        footer = QFrame()
        footer.setStyleSheet("background-color: #0D131F; border-top: 1px solid #1E293B;")
        footer.setFixedHeight(36)
        f_layout = QHBoxLayout(footer)
        f_layout.setContentsMargins(18, 0, 18, 0)
        f_layout.setSpacing(14)

        self.status_lbl = QLabel("🟢 Sẵn sàng. Nhập URL mục tiêu, nhấn '🚀 Chạy Demo', hoặc mở '🌐 Mở Web Console'.")
        self.status_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 600;")
        f_layout.addWidget(self.status_lbl)

        f_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(220)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        f_layout.addWidget(self.progress_bar)

        parent_layout.addWidget(footer)

    # ----------------------------------------------------------------------- #
    # Navigation & UI Actions
    # ----------------------------------------------------------------------- #

    def _switch_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", "true" if i == index else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        if index == 5:
            self._refresh_llm_pool_ui()

    def _on_mode_changed(self, index: int) -> None:
        self.ai_bar.setVisible(index == 1)

    def _open_artex_web_demo(self) -> None:
        url = ensure_artex_web_server(8788)
        webbrowser.open(url)
        self.status_lbl.setText(f"🌐 Đã mở giao diện Web Console tại: {url}")
        self.status_lbl.setStyleSheet("color: #38BDF8; font-size: 11px; font-weight: 700;")

    def _open_runs_folder(self) -> None:
        target_dir = self._last_run_dir if self._last_run_dir.exists() else BASE_DIR / "runs"
        target_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(str(target_dir))
        else:
            subprocess.Popen(["xdg-open", str(target_dir)])

    # ----------------------------------------------------------------------- #
    # Multi-Job Scan Queue & History Management
    # ----------------------------------------------------------------------- #

    def _enqueue_demo_scan(self) -> None:
        """Start the built-in vulnerable Demo Shop server in-process and enqueue a scan."""
        if not self._demo_server_url:
            from tools.demo_target import make_server
            try:
                server = make_server("127.0.0.1", 8099)
            except OSError:
                server = make_server("127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._demo_server_url = f"http://127.0.0.1:{server.server_address[1]}"

        self.target_input.setText(self._demo_server_url)
        self.chk_active.setChecked(True)
        self.chk_injection.setChecked(True)
        self.chk_private.setChecked(True)
        self._enqueue_scan()

    def _enqueue_scan(self) -> None:
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Thiếu thông tin", "Vui lòng nhập URL mục tiêu cần quét!")
            return

        if not (target.startswith("http://") or target.startswith("https://")):
            target = "http://" + target
            self.target_input.setText(target)

        self._job_seq += 1
        job_id = f"#{self._job_seq:02d}"
        is_ai = self.mode_combo.currentIndex() == 1
        planner_label = "AI Planner" if is_ai else "Recon Pro"

        job = ScanJobItem(
            job_id=job_id,
            target=target,
            is_ai=is_ai,
            planner_label=planner_label,
            allow_private=self.chk_private.isChecked(),
            allow_active=self.chk_active.isChecked(),
            allow_injection=self.chk_injection.isChecked(),
            api_key=self.ai_key_input.text().strip() or os.environ.get("DAST_API_KEY", ""),
            model=self.ai_model_input.text().strip() or os.environ.get("DAST_MODEL", "llama-3.3-70b-versatile"),
            base_url=self.ai_base_input.text().strip() or os.environ.get("DAST_BASE_URL", ""),
            status="queued",
        )

        self._jobs[job_id] = job
        self._job_order.insert(0, job_id)  # Newest at top of list
        self._pending_queue.put(job_id)

        # If no job is currently running, select this new job immediately
        if self._running_job_id is None:
            self._selected_job_id = job_id

        self._refresh_queue_ui()
        self._update_queue_badges()

        if self._running_job_id is not None and self._running_job_id != job_id:
            self.status_lbl.setText(
                f"📥 Đã thêm {job_id} ({planner_label} -> {target}) vào Hàng đợi! Sẽ tự động chạy khi lượt hiện tại xong."
            )
            self.status_lbl.setStyleSheet("color: #38BDF8; font-size: 11px; font-weight: 700;")

    def _cancel_selected_or_running_job(self) -> None:
        # Prefer cancelling the currently selected job if it is queued or running
        sel_job = self._jobs.get(self._selected_job_id or "")
        if sel_job and sel_job.status == "queued":
            sel_job.status = "cancelled"
            sel_job.step_text = "Đã huỷ khỏi hàng đợi"
            self._append_job_log_html(sel_job, "[WARN] Đã huỷ Job này khỏi hàng đợi trước khi chạy.")
            self._refresh_queue_ui()
            self._update_queue_badges()
            self._load_job_into_views(sel_job)
            return

        target_job = sel_job if (sel_job and sel_job.status == "running") else self._jobs.get(self._running_job_id or "")
        if target_job and target_job.status == "running":
            target_job.cancel_event.set()
            self.signals.job_log.emit(
                target_job.job_id,
                "[WARN] Người dùng yêu cầu dừng quét. Đang hoàn tất bước hiện tại...",
            )
            self.status_lbl.setText(f"⏳ Đang dừng {target_job.job_id}...")
            self.status_lbl.setStyleSheet("color: #F59E0B; font-size: 11px; font-weight: 700;")

    def _refresh_queue_ui(self) -> None:
        self.queue_list.blockSignals(True)
        self.queue_list.clear()
        selected_row = 0
        for row_idx, jid in enumerate(self._job_order):
            job = self._jobs[jid]
            item = QListWidgetItem(job.display_label())
            item.setData(Qt.ItemDataRole.UserRole, jid)
            self.queue_list.addItem(item)
            if jid == self._selected_job_id:
                selected_row = row_idx
        if self._job_order:
            self.queue_list.setCurrentRow(selected_row)
        self.queue_list.blockSignals(False)

    def _update_queue_badges(self) -> None:
        queued_cnt = sum(1 for j in self._jobs.values() if j.status == "queued")
        running_cnt = sum(1 for j in self._jobs.values() if j.status == "running")
        total_cnt = len(self._jobs)
        self.queue_hdr_lbl.setText(f"📋 HÀNG ĐỢI & LỊCH SỬ ({total_cnt})")

        if running_cnt > 0:
            if queued_cnt > 0:
                self.sb_state_lbl.setText(f"⚡ 1 đang chạy · ⏳ {queued_cnt} đang chờ")
            else:
                self.sb_state_lbl.setText(f"⚡ Đang chạy {self._running_job_id}...")
            self.sb_state_lbl.setStyleSheet("color: #38BDF8; font-size: 11.5px; font-weight: 700;")
            self.progress_bar.setRange(0, 0)
        else:
            self.sb_state_lbl.setText(f"🟢 Sẵn sàng ({total_cnt} lịch sử)")
            self.sb_state_lbl.setStyleSheet("color: #10B981; font-size: 11.5px; font-weight: 700;")
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100 if total_cnt > 0 else 0)

        sel_job = self._jobs.get(self._selected_job_id or "")
        can_cancel = bool(
            (sel_job and sel_job.status in ("queued", "running"))
            or running_cnt > 0
        )
        self.stop_btn.setEnabled(can_cancel)

    def _on_queue_row_selected(self, row: int) -> None:
        if row < 0 or row >= len(self._job_order):
            return
        jid = self._job_order[row]
        self._selected_job_id = jid
        job = self._jobs.get(jid)
        if job:
            self._load_job_into_views(job)
            self._update_queue_badges()

    # ----------------------------------------------------------------------- #
    # Background Queue Worker Loop
    # ----------------------------------------------------------------------- #

    def _queue_worker_loop(self) -> None:
        while True:
            job_id = self._pending_queue.get()
            job = self._jobs.get(job_id)
            if not job or job.status == "cancelled":
                self._pending_queue.task_done()
                continue

            self._running_job_id = job_id
            job.status = "running"
            self.signals.job_started.emit(job_id)

            self._execute_single_job(job)

            self._running_job_id = None
            self._pending_queue.task_done()

    def _execute_single_job(self, job: ScanJobItem) -> None:
        t0 = time.time()
        jid = job.job_id
        self.signals.job_log.emit(jid, "======================================================================")
        self.signals.job_log.emit(
            jid, f"[START] JOB {jid} ({job.planner_label}) — MỤC TIÊU: {job.target}"
        )
        self.signals.job_log.emit(jid, f"[INFO] Bắt đầu lúc: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.signals.job_log.emit(jid, "======================================================================")

        try:
            scope = build_scope_policy(
                job.target,
                allow_private=job.allow_private,
                authorized_by="AI DAST Pro Desktop User",
                authorization_note=f"Authorized via Native Desktop Studio ({jid})",
            )

            permissions = PermissionSet()
            if job.allow_private:
                permissions.grant(Capability.PRIVATE_NETWORK)
            if job.allow_active:
                permissions.grant(Capability.ACTIVE_SCAN)
            if job.allow_injection:
                permissions.grant(Capability.INJECTION_PROBE)
            permissions.assert_forbidden_absent()

            registry = build_default_registry()

            if job.is_ai:
                if not job.api_key:
                    self.signals.job_log.emit(
                        jid, "[WARN] Chưa có AI API Key. Tự động chuyển sang chế độ Scripted Recon Pro."
                    )
                    planner = ScriptedPlanner(max_pages=4)
                    planner_meta = {"name": "scripted-recon-v2"}
                else:
                    pool_cfg = load_llm_pool()
                    pool_models = pool_cfg.get("models", [])
                    active_prim = next((m for m in pool_models if m.get("is_primary") and m.get("status") != "circuit_broken"), None)
                    chosen_model = str(active_prim.get("model")) if active_prim else job.model
                    self.signals.job_log.emit(
                        jid, f"[AI] Khởi tạo AI Master Planner từ LLM Pool (Primary: {chosen_model}, Auto-Failover: BẬT)"
                    )

                    def _on_llm_ev(ev: dict[str, Any]) -> None:
                        st = ev.get("status", "ok")
                        self.signals.job_log.emit(
                            jid,
                            f"[AI-POOL] Model {ev.get('model')} ({ev.get('purpose')}) -> {st.upper()} ({ev.get('latency_ms')} ms): {ev.get('summary')}",
                        )

                    planner = LlmPlanner(
                        registry,
                        model=chosen_model,
                        api_key=job.api_key,
                        base_url=job.base_url or None,
                        fallback_models=pool_models,
                        on_llm_event=_on_llm_ev,
                    )
                    planner_meta = {"name": f"llm:{chosen_model}", "model": chosen_model}
            else:
                self.signals.job_log.emit(
                    jid, "[ENGINE] Chế độ: Scripted Recon Pro (Multi-Endpoint + SQLi/Active Audit)"
                )
                planner = ScriptedPlanner(max_pages=4)
                planner_meta = {"name": "scripted-recon-v2"}

            config = ScanConfig(
                max_steps=36,
                max_tool_calls=90,
                max_pages=15,
                max_requests=150,
                requests_per_second=4.0,
                allow_active_tools=bool(job.allow_active or job.allow_injection),
                require_confirmation=False,
            )

            run_dir = BASE_DIR / "runs" / f"studio_{jid.lstrip('#')}_{int(time.time())}"
            run_dir.mkdir(parents=True, exist_ok=True)

            def event_sink(msg: str) -> None:
                self.signals.job_log.emit(jid, msg)
                if "step" in msg.lower() or "tool" in msg.lower() or "->" in msg:
                    job.step_count += 1
                    self.signals.job_progress.emit(jid, job.step_count, config.max_steps, msg.strip())

            runner = ScanRunner(
                registry,
                planner=planner,
                artifact_dir=run_dir / "artifacts",
                permissions=permissions,
                confirmation=ConfirmationGate(auto_approve=True),
                event_sink=event_sink,
                quiet=False,
                cancel_event=job.cancel_event,
            )

            session = runner.create_session(scope, config)
            runner.run(session)

            report = build_report(
                session,
                registry,
                planner_name=planner_meta.get("name", ""),
                planner_meta=planner_meta,
            )
            write_report(report, run_dir)
            try:
                (run_dir / "session.json").write_text(
                    session.model_dump_json(indent=2), encoding="utf-8"
                )
            except Exception:
                pass

            # Run AI Post-Scan Result Analysis (AI Deep Dive)
            self.signals.job_log.emit(jid, "[AI-ANALYST] Đang phân tích kết quả đạt được, chấm điểm an ninh & sinh code vá lỗi...")
            ai_res = analyze_scan_results(
                target=job.target,
                findings=session.findings,
                technologies=session.surface.technologies,
                facts=session.surface.facts,
                hints=session.surface.hints,
                http_count=len(session.surface.http_history),
                step_count=len(session.trace),
                use_llm=True,
                api_key=job.api_key or None,
                model=job.model or None,
                base_url=job.base_url or None,
            )
            try:
                (run_dir / "ai_analysis.json").write_text(
                    json.dumps(ai_res, indent=2, ensure_ascii=False), encoding="utf-8"
                )
            except Exception:
                pass

            sc_info = ai_res.get("score_info") or {}
            self.signals.job_log.emit(
                jid,
                f"[AI-ANALYST] Điểm An Ninh: {sc_info.get('score', 85)}/100 (Hạng {sc_info.get('grade', 'B')} — {sc_info.get('rating', '')}) | Engine: {ai_res.get('engine', '')}",
            )

            elapsed = round(time.time() - t0, 1)
            job.session = session
            job.report = report
            job.ai_analysis = ai_res
            job.run_dir = str(run_dir)
            job.status = "cancelled" if job.cancel_event.is_set() else "completed"
            job.step_text = f"Hoàn tất ({len(session.trace)} công cụ · {elapsed}s · Điểm AI: {sc_info.get('score', 85)}/100)"

            self.signals.job_log.emit(jid, "======================================================================")
            self.signals.job_log.emit(
                jid, f"[OK] HOÀN TẤT {jid} trong {elapsed}s — Phát hiện {len(session.findings)} lỗ hổng (Điểm An Ninh AI: {sc_info.get('score', 85)}/100)."
            )
            self.signals.job_log.emit(jid, f"[OK] Báo cáo lưu tại: {run_dir}")
            self.signals.job_log.emit(jid, "======================================================================")

            self.signals.job_finished.emit(jid)

        except Exception as exc:
            job.status = "failed"
            job.error_msg = str(exc)
            job.step_text = f"Lỗi: {exc}"
            self.signals.job_log.emit(jid, f"[ERROR] Lỗi trong quá trình quét {jid}: {exc}")
            self.signals.job_failed.emit(jid, str(exc))

    def _load_past_runs_from_disk(self) -> None:
        """Load recent completed scan runs from runs/ into the sidebar history."""
        from app.models.scan import (
            AttackSurface,
            FormRecord,
            HttpExchangeRecord,
            LinkRecord,
            ScanReport,
            ScanSession,
        )

        runs_root = BASE_DIR / "runs"
        if not runs_root.exists():
            return

        run_dirs = sorted(
            (d for d in runs_root.iterdir() if d.is_dir() and (d / "report.json").exists()),
            key=lambda p: p.stat().st_mtime,
        )[-10:]

        for rdir in run_dirs:
            try:
                raw_report = (rdir / "report.json").read_text(encoding="utf-8")
                report = ScanReport.model_validate_json(raw_report)
                sess_path = rdir / "session.json"
                if sess_path.exists():
                    session = ScanSession.model_validate_json(
                        sess_path.read_text(encoding="utf-8")
                    )
                else:
                    surf_d = report.attack_surface or {}
                    pages = {
                        str(p["page_id"]): p
                        for p in surf_d.get("pages", [])
                        if isinstance(p, dict) and "page_id" in p
                    }
                    links = {
                        str(lk["url"]): LinkRecord(
                            url=str(lk["url"]),
                            in_scope=bool(lk.get("in_scope", True)),
                            has_query=bool(lk.get("query_keys")),
                            query_keys=list(lk.get("query_keys") or []),
                        )
                        for lk in surf_d.get("sample_links", [])
                        if isinstance(lk, dict) and "url" in lk
                    }
                    forms = [
                        FormRecord.model_validate(f)
                        for f in surf_d.get("forms", [])
                        if isinstance(f, dict)
                    ]
                    http_hist = [
                        HttpExchangeRecord.model_validate(h)
                        for h in surf_d.get("http_history", [])
                        if isinstance(h, dict)
                    ]
                    surface = AttackSurface(
                        target=report.target,
                        pages=pages,
                        links=links,
                        forms=forms,
                        api_endpoints=list(surf_d.get("api_endpoints") or []),
                        technologies=list(surf_d.get("technologies") or []),
                        http_history=http_hist,
                        tested_endpoints=dict(surf_d.get("tested_endpoints") or {}),
                        facts=list(surf_d.get("facts") or []),
                        hints=list(surf_d.get("hints") or []),
                    )
                    session = ScanSession(
                        scan_id=report.scan_id,
                        status=report.status,
                        scope=report.scope,
                        config=report.config,
                        surface=surface,
                        findings=report.findings,
                        trace=report.tool_trace,
                        started_at=report.started_at,
                        finished_at=report.finished_at,
                        stop_reason=report.stop_reason,
                        counters=report.counters,
                    )

                self._job_seq += 1
                jid = f"#{self._job_seq:02d}"
                pname = str((report.planner or {}).get("name") or "")
                is_ai = pname.startswith("llm:")
                planner_label = "AI Planner" if is_ai else "Recon Pro"

                ai_path = rdir / "ai_analysis.json"
                ai_res: dict[str, Any] = {}
                if ai_path.exists():
                    try:
                        ai_res = json.loads(ai_path.read_text(encoding="utf-8"))
                    except Exception:
                        ai_res = {}
                if not ai_res:
                    ai_res = analyze_scan_results(
                        target=report.target,
                        findings=session.findings,
                        technologies=session.surface.technologies,
                        facts=session.surface.facts,
                        hints=session.surface.hints,
                        http_count=len(session.surface.http_history),
                        step_count=len(session.trace),
                        use_llm=False,
                    )

                sc_val = (ai_res.get("score_info") or {}).get("score", 85)
                job = ScanJobItem(
                    job_id=jid,
                    target=report.target,
                    is_ai=is_ai,
                    planner_label=planner_label,
                    allow_private=True,
                    allow_active=True,
                    allow_injection=True,
                    api_key="",
                    model="",
                    base_url="",
                    status="completed",
                    created_at=report.started_at[11:19] if len(report.started_at) >= 19 else "",
                    session=session,
                    report=report,
                    ai_analysis=ai_res,
                    run_dir=str(rdir),
                    step_count=len(session.trace),
                    step_text=f"Hoàn tất ({len(session.trace)} công cụ · {report.duration_s}s · Điểm AI: {sc_val}/100)",
                )
                self._append_job_log_html(
                    job,
                    f"[START] Lịch sử {jid} ({planner_label}) — Mục tiêu: {report.target} ({report.started_at})",
                )
                for rec in session.trace:
                    self._append_job_log_html(
                        job,
                        f"  step {rec.step}: {rec.tool} -> {rec.status} ({rec.duration_ms} ms): {rec.summary}",
                    )
                self._append_job_log_html(
                    job,
                    f"[AI-ANALYST] Điểm An Ninh: {sc_val}/100 | {ai_res.get('executive_summary', '')}",
                )
                self._append_job_log_html(
                    job,
                    f"[OK] HOÀN TẤT {jid} — Phát hiện {len(session.findings)} lỗ hổng. Thư mục: {rdir}",
                )

                self._jobs[jid] = job
                self._job_order.insert(0, jid)
                self._last_run_dir = rdir
            except Exception:
                continue

        if self._job_order:
            self._selected_job_id = self._job_order[0]
            self._refresh_queue_ui()
            self._update_queue_badges()
            self._load_job_into_views(self._jobs[self._selected_job_id])

    # ----------------------------------------------------------------------- #
    # Signal Handlers
    # ----------------------------------------------------------------------- #

    def _append_job_log_html(self, job: ScanJobItem, text: str) -> str:
        escaped = html.escape(text)
        color = "#CBD5E1"
        if "[OK]" in text or "HOÀN TẤT" in text:
            color = "#10B981"
        elif "[WARN]" in text or "hint" in text.lower():
            color = "#F59E0B"
        elif "[ERROR]" in text or "critical" in text.lower() or "finding" in text.lower():
            color = "#F43F5E"
        elif "[START]" in text or "[AI]" in text or "[AI-POOL]" in text or "[ENGINE]" in text or "===" in text:
            color = "#38BDF8"

        html_line = f"<div style='color:{color}; margin-bottom:2px;'>{escaped}</div>"
        job.logs.append(html_line)
        return html_line

    def _on_job_started(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        cur_sel = self._jobs.get(self._selected_job_id or "")
        if not cur_sel or cur_sel.status != "completed":
            self._selected_job_id = job_id
        self._refresh_queue_ui()
        self._update_queue_badges()
        if self._selected_job_id == job_id:
            self._load_job_into_views(job)
        self.status_lbl.setText(f"🚀 Đang thực thi {job_id} ({job.planner_label}) trên: {job.target} ...")
        self.status_lbl.setStyleSheet("color: #38BDF8; font-size: 11px; font-weight: 700;")

    def _on_job_log(self, job_id: str, text: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        html_line = self._append_job_log_html(job, text)
        if job_id == self._selected_job_id:
            self.console_edit.append(html_line)
            self.console_edit.moveCursor(QTextCursor.MoveOperation.End)
            self.mini_log.append(html_line)
            self.mini_log.moveCursor(QTextCursor.MoveOperation.End)

    def _on_job_progress(self, job_id: str, step: int, max_steps: int, detail: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        short = detail[:85] + "..." if len(detail) > 85 else detail
        job.step_text = f"[{job_id}] Bước #{step}: {short}"
        if job_id == self._selected_job_id:
            self.step_badge_lbl.setText(job.step_text)

    def _on_job_finished(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        if job.run_dir:
            self._last_run_dir = Path(job.run_dir)
        self._refresh_queue_ui()
        self._update_queue_badges()

        if job_id == self._selected_job_id:
            self._load_job_into_views(job)

        total_f = len(getattr(job.session, "findings", []) or []) if job.session else 0
        queued_left = sum(1 for j in self._jobs.values() if j.status == "queued")
        if queued_left > 0:
            self.status_lbl.setText(
                f"✅ {job_id} hoàn tất ({total_f} lỗi). Đang chuyển sang Job tiếp theo trong hàng đợi..."
            )
        else:
            self.status_lbl.setText(
                f"✅ {job_id} ({job.planner_label}) hoàn tất! Phát hiện {total_f} lỗ hổng. Nhấp vào Hàng đợi bên trái để đổi giữa các lượt quét."
            )
        self.status_lbl.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 700;")

    def _on_job_failed(self, job_id: str, err_msg: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return
        self._refresh_queue_ui()
        self._update_queue_badges()
        if job_id == self._selected_job_id:
            self._load_job_into_views(job)
        self.status_lbl.setText(f"❌ {job_id} gặp lỗi: {err_msg}")
        self.status_lbl.setStyleSheet("color: #F43F5E; font-size: 11px; font-weight: 700;")

    # ----------------------------------------------------------------------- #
    # Load Selected Job into Studio Views
    # ----------------------------------------------------------------------- #

    def _load_job_into_views(self, job: ScanJobItem) -> None:
        self.pv_title_lbl.setText(
            f"🔥 KẾT QUẢ CỦA {job.job_id} ({job.planner_label.upper()} — {job.target})"
        )
        self.step_badge_lbl.setText(job.step_text)

        # Logs
        full_log_html = "".join(job.logs)
        self.console_edit.setHtml(full_log_html)
        self.console_edit.moveCursor(QTextCursor.MoveOperation.End)
        self.mini_log.setHtml(full_log_html)
        self.mini_log.moveCursor(QTextCursor.MoveOperation.End)

        if job.session and job.report:
            self._all_findings = list(getattr(job.session, "findings", []) or [])
            self._populate_dashboard(job.session, job.report, job)
            self._populate_findings(self._all_findings)
            self._populate_asset_graph(job.session)
            self._populate_http_history(job.session)
            self._populate_markdown_report(job)
            self._populate_intercept_table(job.session)
            self._refresh_llm_pool_ui()
        else:
            self._all_findings = []
            self._raw_http_history = []
            self.donut_chart.set_counts({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
            state_str = "Đang chờ tới lượt..." if job.status == "queued" else (
                "Đang quét trực tiếp..." if job.status == "running" else job.status.upper()
            )
            self.card_total.set_metric("...", state_str)
            self.card_crit_high.set_metric("...", f"Job {job.job_id} ({job.planner_label})")
            self.card_endpoints.set_metric("...", job.target)
            self.card_requests.set_metric("...", f"Tạo lúc {job.created_at}")
            self.dash_summary_browser.setHtml(
                f"<div style='font-family:Segoe UI,sans-serif; padding:18px; color:#94A3B8;'>"
                f"<h3 style='color:#38BDF8; margin-top:0;'>⏳ Job {job.job_id} ({job.planner_label}) — {state_str}</h3>"
                f"<p>Mục tiêu: <b style='color:#F8FAFC;'>{html.escape(job.target)}</b></p>"
                f"<p>Kết quả chi tiết, biểu đồ và bản đồ tấn công sẽ tự động cập nhật ngay khi lượt quét này hoàn tất.</p>"
                f"</div>"
            )
            self._populate_findings([])
            self.asset_tree.clear()
            self.http_table.setRowCount(0)
            self.report_md_edit.setPlainText(f"Đang thực thi {job.job_id} ({job.target})...")
            self.approval_table.setRowCount(0)

    # ----------------------------------------------------------------------- #
    # Populate Views
    # ----------------------------------------------------------------------- #

    def _populate_dashboard(self, session: Any, report: Any, job: ScanJobItem) -> None:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self._all_findings:
            sev = getattr(f, "severity", "INFO")
            s_key = sev.name.upper() if hasattr(sev, "name") else str(sev).upper()
            counts[s_key] = counts.get(s_key, 0) + 1

        self.donut_chart.set_counts(counts)

        total = sum(counts.values())
        crit_high = counts["CRITICAL"] + counts["HIGH"]
        surface = getattr(session, "surface", None)
        links_cnt = len(surface.links) if surface else 0
        tested_cnt = len(surface.tested_endpoints) if surface else 0
        http_cnt = len(surface.http_history) if surface else 0
        dur = round(getattr(report, "duration_s", 0.0), 1)

        self.card_total.set_metric(
            str(total),
            f"{counts['MEDIUM']} Medium · {counts['LOW']} Low · {counts['INFO']} Info",
        )
        self.card_crit_high.set_metric(
            str(crit_high),
            f"{counts['CRITICAL']} Critical · {counts['HIGH']} High",
        )
        self.card_endpoints.set_metric(
            f"{tested_cnt} / {max(tested_cnt, links_cnt)}",
            f"Đã kiểm tra {tested_cnt} endpoints",
        )
        self.card_requests.set_metric(f"{http_cnt} reqs", f"Thời gian: {dur}s ({job.planner_label})")

        rows_html = ""
        for f in self._all_findings[:8]:
            sev = getattr(f, "severity", "INFO")
            s_key = sev.name.upper() if hasattr(sev, "name") else str(sev).upper()
            col = SEV_COLORS.get(s_key, "#64748B")
            bg = SEV_BG_COLORS.get(s_key, "#1E293B")
            title = html.escape(str(getattr(f, "title", "")))
            loc = html.escape(str(getattr(f, "location", "") or getattr(f, "url", "")))
            owasp = html.escape(str(getattr(f, "owasp", "")))
            rows_html += f"""
            <div style="background-color:#131C2E; border:1px solid #1E293B; border-left:4px solid {col};
                        border-radius:6px; padding:9px 12px; margin-bottom:7px;">
                <span style="background-color:{bg}; color:{col}; font-weight:bold; font-size:10px;
                             padding:2px 6px; border-radius:4px;">{s_key}</span>
                <span style="color:#F8FAFC; font-weight:bold; font-size:13px; margin-left:6px;">{title}</span>
                <span style="color:#64748B; font-size:11px; float:right;">{owasp}</span>
                <div style="color:#93C5FD; font-family:Consolas,monospace; font-size:11px; margin-top:4px;">
                    📍 {loc}
                </div>
            </div>
            """

        if not rows_html:
            rows_html = (
                "<div style='color:#10B981; font-size:14px; font-weight:bold; padding:20px;'>"
                "🎉 Không phát hiện lỗ hổng bảo mật nào trên mục tiêu này!</div>"
            )

        techs = ", ".join(surface.technologies) if (surface and surface.technologies) else "Chưa định danh"

        # Render AI Post-Scan Result Analysis Box (AI Deep Dive)
        ai = job.ai_analysis or {}
        if not ai:
            ai = analyze_scan_results(
                target=job.target,
                findings=self._all_findings,
                technologies=surface.technologies if surface else [],
                facts=surface.facts if surface else [],
                hints=surface.hints if surface else [],
                http_count=http_cnt,
                step_count=len(getattr(session, "trace", []) or []),
                use_llm=False,
            )
            job.ai_analysis = ai

        sc = ai.get("score_info") or {"score": 85, "grade": "B", "rating": "LOW RISK", "color": "#38BDF8"}
        sc_col = sc.get("color", "#38BDF8")
        exec_sum = html.escape(str(ai.get("executive_summary") or ""))
        llm_comm = html.escape(str(ai.get("llm_commentary") or ""))
        chains_html = "".join(
            f"<div style='color:#E2E8F0; font-size:12px; margin-bottom:5px;'>• {html.escape(str(c))}</div>"
            for c in (ai.get("attack_chains") or [])[:3]
        )
        rems_html = "".join(
            f"<div style='color:#D1FAE5; font-size:12px; margin-bottom:4px;'>🔧 <b>[{html.escape(str(r.get('priority','')))}]</b> {html.escape(str(r.get('title','')))}</div>"
            for r in (ai.get("remediations") or [])[:3]
        )

        ai_box_html = f"""
        <div style="background-color:#111827; border:1.5px solid #A855F7; border-radius:8px; padding:12px 14px; margin-bottom:12px;">
            <div style="margin-bottom:6px;">
                <span style="background-color:#4C1D95; color:#F5F3FF; font-weight:800; font-size:10.5px; padding:3px 8px; border-radius:4px;">
                    🤖 AI PHÂN TÍCH KẾT QUẢ ĐẠT ĐƯỢC ({html.escape(str(ai.get('engine', 'Hybrid Security Engine')))})
                </span>
                <span style="background-color:#0F172A; color:{sc_col}; border:1px solid {sc_col}; font-weight:900; font-size:11.5px; padding:3px 10px; border-radius:4px; margin-left:8px;">
                    ĐIỂM AN NINH: {sc.get('score', 85)}/100 · HẠNG {html.escape(str(sc.get('grade', 'B')))} ({html.escape(str(sc.get('rating', '')))})
                </span>
            </div>
            <div style="color:#F8FAFC; font-size:12.5px; line-height:1.5; margin-bottom:8px;">{exec_sum}</div>
            {f'<div style="background-color:#1E1030; border-left:3px solid #A855F7; padding:8px 10px; border-radius:5px; color:#E9D5FF; font-size:12px; white-space:pre-line; margin-bottom:8px;"><b>💬 Nhận định chiến lược từ Cụm LLM Pool:</b><br>{llm_comm}</div>' if llm_comm else ''}
            <div style="color:#FB7185; font-size:11px; font-weight:800; margin-top:4px; margin-bottom:3px;">⛓️ TƯƠNG QUAN RỦI RO & CHUỖI TÁC ĐỘNG:</div>
            {chains_html}
            <div style="color:#34D399; font-size:11px; font-weight:800; margin-top:6px; margin-bottom:3px;">🛠️ LỘ TRÌNH KHẮC PHỤC ƯU TIÊN (Xem mã vá lỗi ở tab Báo cáo Markdown / Chi tiết Lỗ hổng):</div>
            {rems_html}
        </div>
        """

        summary_html = f"""
        <div style="font-family:'Segoe UI',sans-serif;">
            <div style="background-color:#0F172A; border:1px solid #1E293B; border-radius:6px; padding:8px 12px; margin-bottom:10px;">
                <span style="color:#94A3B8; font-size:11px; font-weight:bold;">🖥️ CÔNG NGHỆ ({html.escape(job.job_id)} - {html.escape(job.planner_label)}):</span>
                <span style="color:#38BDF8; font-size:12px; font-weight:bold; margin-left:6px;">{html.escape(techs)}</span>
            </div>
            {ai_box_html}
            {rows_html}
        </div>
        """
        self.dash_summary_browser.setHtml(summary_html)

    def _populate_findings(self, findings: list[Any]) -> None:
        counts = {"ALL": len(findings), "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = getattr(f, "severity", "INFO")
            s_key = sev.name.upper() if hasattr(sev, "name") else str(sev).upper()
            counts[s_key] = counts.get(s_key, 0) + 1

        labels = {
            "ALL": f"Tất cả ({counts['ALL']})",
            "CRITICAL": f"🔴 Critical ({counts['CRITICAL']})",
            "HIGH": f"🟠 High ({counts['HIGH']})",
            "MEDIUM": f"🟡 Medium ({counts['MEDIUM']})",
            "LOW": f"🔵 Low ({counts['LOW']})",
            "INFO": f"⚪ Info ({counts['INFO']})",
        }
        for k, btn in self.filter_pills.items():
            btn.setText(labels[k])

        self._apply_findings_filter()

    def _set_sev_filter(self, sev_key: str) -> None:
        self._active_sev_filter = sev_key
        for k, btn in self.filter_pills.items():
            btn.setProperty("active", "true" if k == sev_key else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self._apply_findings_filter()

    def _apply_findings_filter(self) -> None:
        query = self.search_finding_input.text().strip().lower()
        self.findings_list.clear()
        self._filtered_findings: list[Any] = []

        for f in self._all_findings:
            sev = getattr(f, "severity", "INFO")
            s_key = sev.name.upper() if hasattr(sev, "name") else str(sev).upper()

            if self._active_sev_filter != "ALL" and s_key != self._active_sev_filter:
                continue

            title = str(getattr(f, "title", ""))
            url = str(getattr(f, "url", ""))
            loc = str(getattr(f, "location", ""))
            owasp = str(getattr(f, "owasp", ""))
            cwe = str(getattr(f, "cwe", ""))

            if query and not any(query in field.lower() for field in (title, url, loc, owasp, cwe)):
                continue

            self._filtered_findings.append(f)
            icon_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
            badge_icon = icon_map.get(s_key, "⚪")
            sub = loc or url
            item_text = f"{badge_icon} [{s_key}]  {title}\n     📍 {sub}"
            item = QListWidgetItem(item_text)
            self.findings_list.addItem(item)

        if self._filtered_findings:
            self.findings_list.setCurrentRow(0)
        else:
            self.finding_inspector.setHtml(
                "<div style='color:#64748B; text-align:center; margin-top:80px; font-size:13px;'>"
                "Không có lỗ hổng nào khớp với bộ lọc hiện tại.</div>"
            )

    def _on_finding_selected(self, row: int, retest_banner_html: str = "") -> None:
        if row < 0 or row >= len(getattr(self, "_filtered_findings", [])):
            return
        f = self._filtered_findings[row]
        sev = getattr(f, "severity", "INFO")
        s_key = sev.name.upper() if hasattr(sev, "name") else str(sev).upper()
        conf = getattr(f, "confidence", "MEDIUM")
        c_key = conf.name.upper() if hasattr(conf, "name") else str(conf).upper()
        cat = getattr(f, "category", "")
        cat_str = cat.value if hasattr(cat, "value") else str(cat)

        col = SEV_COLORS.get(s_key, "#64748B")
        bg = SEV_BG_COLORS.get(s_key, "#1E293B")

        title = html.escape(str(getattr(f, "title", "")))
        url = html.escape(str(getattr(f, "url", "")))
        loc = html.escape(str(getattr(f, "location", "")))
        desc = html.escape(str(getattr(f, "description", "Không có mô tả.")))
        impact = html.escape(str(getattr(f, "impact", "Chưa có thông tin tác động cụ thể.")))
        rec = html.escape(str(getattr(f, "recommendation", "Chưa có khuyến nghị khắc phục.")))
        owasp = html.escape(str(getattr(f, "owasp", "N/A")))
        cwe = html.escape(str(getattr(f, "cwe", "N/A")))
        tools = ", ".join(getattr(f, "source_tools", []) or [])

        # Automatic AI Deep Dive Analysis when clicked
        job = self._jobs.get(self._selected_job_id or "")
        surface = getattr(job.session, "surface", None) if (job and job.session) else None
        techs = surface.technologies if surface else []

        cache_key = f"{cat_str}_{title}_{url}"
        if not hasattr(self, "_finding_ai_cache"):
            self._finding_ai_cache: dict[str, Any] = {}

        if cache_key not in self._finding_ai_cache:
            eff_key = self.ai_key_input.text().strip() or os.environ.get("DAST_API_KEY", "")
            self._finding_ai_cache[cache_key] = analyze_single_finding(
                f,
                technologies=techs,
                use_llm=bool(eff_key),
            )

        ai_res = self._finding_ai_cache[cache_key]
        root_c = html.escape(str(ai_res.get("root_cause") or ""))
        scen = html.escape(str(ai_res.get("exploit_scenario") or ""))
        patch = html.escape(str(ai_res.get("code_patch") or ""))
        ai_adv = html.escape(str(ai_res.get("ai_advice") or ai_res.get("llm_advice") or ""))
        engine_lbl = html.escape(str(ai_res.get("engine") or "AI Security Analyst"))
        lat_ms = ai_res.get("latency_ms", 10)

        ai_banner_html = f"""
        <div style="background-color:#130E24; border:1.5px solid #A855F7; border-radius:8px; padding:12px 14px; margin-bottom:14px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <span style="background-color:#4C1D95; color:#F5F3FF; font-weight:800; font-size:11px; padding:3px 8px; border-radius:4px;">
                    🤖 AI PHÂN TÍCH CHUYÊN SÂU ({engine_lbl} · {lat_ms} ms)
                </span>
                <span style="color:#C084FC; font-size:11px; font-weight:700;">Tự động phân tích khi nhấp chọn</span>
            </div>
            <div style="color:#F8FAFC; font-size:12.5px; line-height:1.5; margin-bottom:6px;">
                <b style="color:#38BDF8;">🔍 Nguyên nhân gốc rễ (Root Cause):</b> {root_c}
            </div>
            <div style="color:#FECDD3; font-size:12px; line-height:1.5; margin-bottom:6px;">
                <b style="color:#FB7185;">⚠️ Kịch bản Rủi ro & Khai thác (Exploit Scenario):</b> {scen}
            </div>
            {f'<div style="background:#0F091C; border-left:3px solid #A855F7; padding:8px 10px; border-radius:5px; color:#E9D5FF; font-size:12px; white-space:pre-line; margin-bottom:8px;"><b>🧠 Nhận định từ AI Security Advisor:</b><br>{ai_adv}</div>' if ai_adv else ''}
            <div style="color:#34D399; font-weight:800; font-size:11.5px; margin-top:6px;">🛠️ MẪU CODE / CẤU HÌNH VÁ LỖI CỤ THỂ (REMEDIATION PATCH):</div>
            <pre style="background:#070A12; color:#6EE7B7; border:1px solid #065F46; padding:10px; border-radius:6px; font-size:11px; margin-top:4px;">{patch}</pre>
        </div>
        """

        ev_html = ""
        for idx, ev in enumerate(getattr(f, "evidence", []) or [], 1):
            e_tool = html.escape(str(getattr(ev, "tool", "")))
            e_url = html.escape(str(getattr(ev, "url", "")))
            e_loc = html.escape(str(getattr(ev, "location", "")))
            e_obs = html.escape(str(getattr(ev, "observed", "")))
            e_exp = html.escape(str(getattr(ev, "expected", "")))
            raw_dict = getattr(ev, "raw", {}) or {}
            raw_json = html.escape(json.dumps(raw_dict, indent=2, ensure_ascii=False)) if raw_dict else ""

            ev_html += f"""
            <div style="background-color:#090D16; border:1px solid #1E293B; border-radius:6px; padding:10px; margin-bottom:8px;">
                <div style="color:#38BDF8; font-size:11px; font-weight:bold; margin-bottom:4px;">
                    🔬 Bằng chứng #{idx} — Công cụ: <code>{e_tool}</code>
                </div>
                <div style="color:#94A3B8; font-size:11px;"><b>URL:</b> <code>{e_url}</code> | <b>Vị trí:</b> <code>{e_loc}</code></div>
                <div style="color:#F87171; font-size:11px; margin-top:4px;"><b>Quan sát thực tế (Observed):</b> <code>{e_obs}</code></div>
                <div style="color:#34D399; font-size:11px; margin-top:2px;"><b>Kỳ vọng an toàn (Expected):</b> <code>{e_exp}</code></div>
                {f'<pre style="background:#05080F; color:#93C5FD; padding:8px; border-radius:4px; font-size:10px; margin-top:6px;">{raw_json}</pre>' if raw_json else ''}
            </div>
            """

        if not ev_html:
            ev_html = "<div style='color:#64748B; font-size:12px;'>Không có dữ liệu bằng chứng thô.</div>"

        detail_html = f"""
        <div style="font-family:'Segoe UI',sans-serif; line-height:1.5;">
            {retest_banner_html}
            <div style="border-bottom:1px solid #1E293B; padding-bottom:12px; margin-bottom:14px;">
                <span style="background-color:{bg}; color:{col}; font-weight:800; font-size:11px;
                             padding:4px 10px; border-radius:4px; border:1px solid {col};">{s_key}</span>
                <span style="background-color:#1E293B; color:#CBD5E1; font-weight:700; font-size:11px;
                             padding:4px 8px; border-radius:4px; margin-left:6px;">Độ tin cậy: {c_key}</span>
                <span style="background-color:#172554; color:#60A5FA; font-weight:700; font-size:11px;
                             padding:4px 8px; border-radius:4px; margin-left:6px;">{html.escape(cat_str)}</span>
                <h2 style="color:#F8FAFC; margin:10px 0 6px 0; font-size:18px;">{title}</h2>
                <div style="color:#93C5FD; font-family:Consolas,monospace; font-size:12px;">
                    🌐 <b>URL:</b> {url} &nbsp;&nbsp;|&nbsp;&nbsp; 📍 <b>Vị trí:</b> {loc or 'Origin-wide'}
                </div>
                <div style="color:#94A3B8; font-size:11px; margin-top:4px;">
                    🛡️ <b>OWASP:</b> {owasp} &nbsp;&nbsp;•&nbsp;&nbsp; 🔖 <b>CWE:</b> {cwe} &nbsp;&nbsp;•&nbsp;&nbsp; 🔧 <b>Tools:</b> {html.escape(tools)}
                </div>
            </div>

            {ai_banner_html}

            <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:12px; margin-bottom:12px;">
                <div style="color:#38BDF8; font-weight:800; font-size:11px; margin-bottom:4px;">📖 MÔ TẢ CHI TIẾT (DESCRIPTION)</div>
                <div style="color:#E2E8F0; font-size:13px;">{desc}</div>
            </div>

            <div style="background-color:#1C1219; border:1px solid #3B1219; border-radius:8px; padding:12px; margin-bottom:12px;">
                <div style="color:#FB7185; font-weight:800; font-size:11px; margin-bottom:4px;">💥 TÁC ĐỘNG BẢO MẬT (IMPACT)</div>
                <div style="color:#FECDD3; font-size:13px;">{impact}</div>
            </div>

            <div style="background-color:#0B241E; border:1px solid #064E3B; border-radius:8px; padding:12px; margin-bottom:14px;">
                <div style="color:#34D399; font-weight:800; font-size:11px; margin-bottom:4px;">🛠️ HƯỚNG DẪN KHẮC PHỤC (REMEDIATION)</div>
                <div style="color:#D1FAE5; font-size:13px;">{rec}</div>
            </div>

            <div style="margin-top:8px;">
                <div style="color:#94A3B8; font-weight:800; font-size:11px; margin-bottom:8px;">🔬 BẰNG CHỨNG KỸ THUẬT (TRACEABLE EVIDENCE)</div>
                {ev_html}
            </div>
        </div>
        """
        self.finding_inspector.setHtml(detail_html)
        if not retest_banner_html:
            self.status_lbl.setText(f"🤖 Đã phân tích AI & nạp mã vá lỗi cho: {title} ({engine_lbl} · {lat_ms} ms)")
            self.status_lbl.setStyleSheet("color: #C084FC; font-size: 11px; font-weight: 700;")

    def _run_ai_analysis_for_current_job(self) -> None:
        job = self._jobs.get(self._selected_job_id or "")
        if not job or not job.session:
            QMessageBox.information(self, "AI Phân Tích", "Vui lòng chọn hoặc chạy một chiến dịch quét trước khi phân tích!")
            return

        self.status_lbl.setText(f"🤖 Đang gửi kết quả {job.job_id} ({job.target}) tới Cụm LLM Pool để phân tích chuyên sâu...")
        self.status_lbl.setStyleSheet("color: #A855F7; font-size: 11px; font-weight: 700;")
        QApplication.processEvents()

        surface = getattr(job.session, "surface", None)
        ai_res = analyze_scan_results(
            target=job.target,
            findings=job.session.findings,
            technologies=surface.technologies if surface else [],
            facts=surface.facts if surface else [],
            hints=surface.hints if surface else [],
            http_count=len(surface.http_history) if surface else 0,
            step_count=len(job.session.trace),
            use_llm=True,
            api_key=self.ai_key_input.text().strip() or None,
            model=self.ai_model_input.text().strip() or None,
            base_url=self.ai_base_input.text().strip() or None,
        )
        job.ai_analysis = ai_res
        if job.run_dir:
            try:
                (Path(job.run_dir) / "ai_analysis.json").write_text(
                    json.dumps(ai_res, indent=2, ensure_ascii=False), encoding="utf-8"
                )
            except Exception:
                pass

        self._populate_dashboard(job.session, job.report, job)
        self._populate_markdown_report(job)
        sc = (ai_res.get("score_info") or {}).get("score", 85)
        self.status_lbl.setText(
            f"✅ Hoàn tất AI Phân Tích Kết Quả {job.job_id}: Điểm An Ninh {sc}/100 ({ai_res.get('engine', '')} · {ai_res.get('latency_ms', 0)} ms)"
        )
        self.status_lbl.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 700;")

    def _ai_analyze_selected_finding(self) -> None:
        row = self.findings_list.currentRow()
        if row < 0 or row >= len(getattr(self, "_filtered_findings", [])):
            QMessageBox.information(self, "Chọn lỗ hổng", "Vui lòng chọn một lỗ hổng trong danh sách bên trái để AI phân tích!")
            return
        f = self._filtered_findings[row]
        title = str(getattr(f, "title", ""))
        self.status_lbl.setText(f"🤖 AI đang phân tích nguyên nhân gốc rễ & sinh code vá lỗi cho '{title}'...")
        self.status_lbl.setStyleSheet("color: #A855F7; font-size: 11px; font-weight: 700;")
        QApplication.processEvents()

        job = self._jobs.get(self._selected_job_id or "")
        surface = getattr(job.session, "surface", None) if (job and job.session) else None
        techs = surface.technologies if surface else []

        res = analyze_single_finding(finding=f, technologies=techs, use_llm=True)
        root_c = html.escape(str(res.get("root_cause") or ""))
        scen = html.escape(str(res.get("exploit_scenario") or ""))
        patch = html.escape(str(res.get("code_patch") or ""))
        llm_adv = html.escape(str(res.get("llm_advice") or ""))
        eng = html.escape(str(res.get("engine") or "AI Security Analyst"))

        banner = f"""
        <div style="background-color:#170F26; border:1.5px solid #A855F7; border-radius:8px; padding:12px 14px; margin-bottom:14px;">
            <div style="color:#C084FC; font-weight:800; font-size:13px; margin-bottom:6px;">
                🤖 BÁO CÁO AI PHÂN TÍCH CHUYÊN SÂU & MẪU CODE VÁ LỖI ({eng} · {res.get('latency_ms', 0)} ms)
            </div>
            <div style="color:#E2E8F0; font-size:12px; margin-bottom:6px;">
                <b style="color:#38BDF8;">🔍 Nguyên nhân gốc rễ:</b> {root_c}
            </div>
            <div style="color:#FECDD3; font-size:12px; margin-bottom:6px;">
                <b style="color:#FB7185;">⚠️ Cơ chế Rủi ro:</b> {scen}
            </div>
            {f'<div style="background:#0F091C; border-left:3px solid #A855F7; padding:8px; border-radius:4px; color:#E9D5FF; font-size:12px; white-space:pre-line; margin-bottom:8px;"><b>🧠 Nhận định từ LLM Pool:</b><br>{llm_adv}</div>' if llm_adv else ''}
            <div style="color:#34D399; font-weight:800; font-size:11.5px; margin-top:6px;">🛠️ MẪU CODE / CẤU HÌNH VÁ LỖI (REMEDIATION PATCH):</div>
            <pre style="background:#070A12; color:#6EE7B7; border:1px solid #065F46; padding:9px; border-radius:6px; font-size:11px; margin-top:4px;">{patch}</pre>
        </div>
        """
        self._on_finding_selected(row, retest_banner_html=banner)
        self.status_lbl.setText(f"✅ Đã hiển thị phân tích AI & code vá lỗi cho '{title}' ({res.get('latency_ms', 0)} ms)")
        self.status_lbl.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 700;")

    def _retest_selected_finding(self) -> None:
        row = self.findings_list.currentRow()
        if row < 0 or row >= len(getattr(self, "_filtered_findings", [])):
            QMessageBox.information(self, "Chọn lỗ hổng", "Vui lòng chọn một lỗ hổng trong danh sách để kiểm tra lại!")
            return
        f = self._filtered_findings[row]
        url = str(getattr(f, "url", "") or getattr(f, "location", ""))
        cat = getattr(f, "category", "")
        cat_str = cat.value if hasattr(cat, "value") else str(cat)
        title = str(getattr(f, "title", ""))

        self.status_lbl.setText(f"🔄 Đang kiểm tra lại (Retest) lỗ hổng '{title}' trên {url}...")
        self.status_lbl.setStyleSheet("color: #38BDF8; font-size: 11px; font-weight: 700;")
        QApplication.processEvents()

        res = BACKEND.retest_finding(url=url, category=cat_str, title=title)
        verdict = html.escape(str(res.get("verdict") or ""))
        detail = html.escape(str(res.get("detail") or ""))
        is_vuln = bool(res.get("still_vulnerable", True))
        b_col = "#F43F5E" if is_vuln else "#10B981"
        b_bg = "#3B1219" if is_vuln else "#064E3B"

        banner = f"""
        <div style="background-color:{b_bg}; border:1.5px solid {b_col}; border-radius:8px; padding:12px; margin-bottom:14px;">
            <div style="color:{b_col}; font-weight:800; font-size:13px;">🔬 KẾT QUẢ KIỂM TRA LẠI TRỰC TIẾP (1-CLICK RETEST): {verdict}</div>
            <div style="color:#E2E8F0; font-size:12px; margin-top:4px;">{detail}</div>
        </div>
        """
        self._on_finding_selected(row, retest_banner_html=banner)
        self.status_lbl.setText(f"✅ Hoàn tất Retest: {res.get('verdict')} ({res.get('elapsed_ms', 0)} ms)")
        self.status_lbl.setStyleSheet(f"color: {b_col}; font-size: 11px; font-weight: 700;")

    def _jump_to_finding_traffic(self) -> None:
        row = self.findings_list.currentRow()
        if row < 0 or row >= len(getattr(self, "_filtered_findings", [])):
            self._switch_page(3)
            return
        f = self._filtered_findings[row]
        url = str(getattr(f, "url", "") or "")
        self._switch_page(3)
        self.http_search_input.setText(url)

    def _populate_asset_graph(self, session: Any) -> None:
        self.asset_tree.clear()
        surface = getattr(session, "surface", None)
        if not surface:
            return

        tree_data = surface.to_asset_tree(getattr(session, "findings", []))
        root_item = QTreeWidgetItem(self.asset_tree)
        root_item.setText(0, f"🎯 {tree_data.get('name', 'Target')}")
        root_item.setText(1, str(tree_data.get("status", "tested")).upper())
        root_item.setText(2, ", ".join(tree_data.get("tested", [])))

        for group in tree_data.get("children", []):
            grp_item = QTreeWidgetItem(root_item)
            grp_item.setText(0, f"📂 {group.get('name', '')}")
            for node in group.get("children", []):
                n_item = QTreeWidgetItem(grp_item)
                status = node.get("status", "untested")
                icon = "🔴" if status == "vulnerable" else ("🔵" if status == "tested" else "⚪")
                n_item.setText(0, f"{icon} {node.get('name', '')}")
                n_item.setText(1, status.upper())

                tested_list = node.get("tested", [])
                finds_list = [f.get("title", "") for f in node.get("findings", [])]
                summary_parts = []
                if finds_list:
                    summary_parts.append(f"⚠️ Lỗi: {', '.join(finds_list)}")
                if tested_list:
                    summary_parts.append(f"✔ Tools: {', '.join(tested_list)}")
                n_item.setText(2, " | ".join(summary_parts) if summary_parts else "Chưa quét sâu")

        self.asset_tree.expandAll()

        # Build Exploration Chain HTML (Exploration Chain)
        trace_list = getattr(session, "trace", []) or []
        chain_steps_html = f"""
        <div style="background:#0B1324; border-left:3px solid #38BDF8; padding:8px 10px; border-radius:5px; margin-bottom:7px;">
            <span style="color:#38BDF8; font-weight:800; font-size:10px;">🏁 KHỞI ĐIỂM (START)</span>
            <div style="color:#F8FAFC; font-weight:bold; font-size:12px;">Khởi tạo Chiến dịch Trinh sát: {html.escape(str(surface.target))}</div>
        </div>
        """
        for idx, rec in enumerate(trace_list[:15], 1):
            tname = html.escape(str(getattr(rec, "tool", "")))
            thought = html.escape(str(getattr(rec, "thought", "") or f"Thực thi {tname}"))
            summary = html.escape(str(getattr(rec, "summary", "")))
            dur_ms = getattr(rec, "duration_ms", 0)
            chain_steps_html += f"""
            <div style="background:#0F172A; border-left:3px solid #60A5FA; padding:8px 10px; border-radius:5px; margin-bottom:7px;">
                <span style="color:#60A5FA; font-weight:800; font-size:10px;">🔧 BƯỚC #{idx} · {tname.upper()} ({dur_ms} ms)</span>
                <div style="color:#E2E8F0; font-weight:bold; font-size:12px;">{thought}</div>
                <div style="color:#94A3B8; font-size:11px; margin-top:2px;">↳ {summary}</div>
            </div>
            """

        for f in getattr(session, "findings", [])[:6]:
            sev = getattr(f, "severity", "INFO")
            s_key = sev.name.upper() if hasattr(sev, "name") else str(sev).upper()
            col = SEV_COLORS.get(s_key, "#F43F5E")
            chain_steps_html += f"""
            <div style="background:#1C1219; border-left:3px solid {col}; padding:8px 10px; border-radius:5px; margin-bottom:7px;">
                <span style="color:{col}; font-weight:800; font-size:10px;">💥 PHÁT HIỆN LỖ HỔNG ({s_key})</span>
                <div style="color:#FECDD3; font-weight:bold; font-size:12px;">{html.escape(str(getattr(f, 'title', '')))}</div>
                <div style="color:#FDA4AF; font-size:11px;">📍 {html.escape(str(getattr(f, 'location', '') or getattr(f, 'url', '')))}</div>
            </div>
            """

        facts_html = "".join(
            f"<li style='margin-bottom:5px; color:#E2E8F0;'>{html.escape(f)}</li>"
            for f in (surface.facts or [])
        ) or "<li style='color:#64748B;'>Chưa có ghi nhận.</li>"

        hints_html = "".join(
            f"<li style='margin-bottom:5px; color:#FDE047;'>{html.escape(h)}</li>"
            for h in (surface.hints or [])
        ) or "<li style='color:#64748B;'>Không có gợi ý mở rộng.</li>"

        techs = ", ".join(surface.technologies) if surface.technologies else "Chưa phát hiện"

        intel_html = f"""
        <div style="font-family:'Segoe UI',sans-serif; line-height:1.5;">
            <div style="background:#111827; border:1px solid #1E293B; border-radius:8px; padding:12px; margin-bottom:12px;">
                <div style="color:#38BDF8; font-weight:800; font-size:11px; margin-bottom:6px;">🖥️ CÔNG NGHỆ & FINGERPRINT</div>
                <div style="color:#F8FAFC; font-size:13px; font-weight:bold;">{html.escape(techs)}</div>
            </div>

            <div style="background:#111827; border:1px solid #1E293B; border-radius:8px; padding:12px; margin-bottom:12px;">
                <div style="color:#38BDF8; font-weight:800; font-size:11px; margin-bottom:8px;">⛓️ CHUỖI SUY LUẬN & KHAI THÁC AI (EXPLORATION CHAIN)</div>
                {chain_steps_html}
            </div>

            <div style="background:#111827; border:1px solid #1E293B; border-radius:8px; padding:12px; margin-bottom:12px;">
                <div style="color:#10B981; font-weight:800; font-size:11px; margin-bottom:6px;">📌 DỮ KIỆN QUAN SÁT (OBSERVED FACTS)</div>
                <ul style="margin:0; padding-left:18px; font-size:12px;">{facts_html}</ul>
            </div>

            <div style="background:#111827; border:1px solid #1E293B; border-radius:8px; padding:12px;">
                <div style="color:#F59E0B; font-weight:800; font-size:11px; margin-bottom:6px;">💡 GỢI Ý ĐIỀU TRA TIẾP THEO (AI HINTS)</div>
                <ul style="margin:0; padding-left:18px; font-size:12px;">{hints_html}</ul>
            </div>
        </div>
        """
        self.intel_browser.setHtml(intel_html)

    def _populate_http_history(self, session: Any) -> None:
        surface = getattr(session, "surface", None)
        self._raw_http_history = list(getattr(surface, "http_history", []) if surface else [])
        self._apply_http_filter()

    def _reset_http_filter(self) -> None:
        self.http_method_combo.setCurrentIndex(0)
        self.http_status_combo.setCurrentIndex(0)
        self.http_search_input.clear()

    def _apply_http_filter(self) -> None:
        history = getattr(self, "_raw_http_history", [])
        method_flt = self.http_method_combo.currentText()
        status_idx = self.http_status_combo.currentIndex()
        query = self.http_search_input.text().strip().lower()

        filtered = []
        for idx, rec in enumerate(history, 1):
            m = str(rec.method or "GET").upper()
            st = str(rec.status_code) if rec.status_code is not None else "ERR"
            url = str(rec.requested_url or "")
            ctype = str(rec.content_type or "-")

            if method_flt != "Tất cả Method" and m != method_flt:
                continue
            if status_idx == 1 and not st.startswith("2"):
                continue
            if status_idx == 2 and not st.startswith("3"):
                continue
            if status_idx == 3 and not st.startswith("4"):
                continue
            if status_idx == 4 and not st.startswith("5"):
                continue
            if query and query not in url.lower() and query not in ctype.lower():
                continue
            filtered.append((idx, rec))

        self.http_count_lbl.setText(f"Hiển thị {len(filtered)} / {len(history)} gói tin")
        self.http_table.setRowCount(len(filtered))

        for row_i, (orig_idx, rec) in enumerate(filtered):
            status_str = str(rec.status_code) if rec.status_code is not None else "ERR"
            vals = [
                str(orig_idx),
                rec.method,
                status_str,
                rec.requested_url,
                rec.content_type or "-",
                f"{rec.body_bytes} B",
                f"{rec.total_ms} ms",
            ]
            for col_i, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if col_i == 2:
                    if status_str.startswith("2"):
                        item.setForeground(QColor("#10B981"))
                    elif status_str.startswith("3"):
                        item.setForeground(QColor("#38BDF8"))
                    elif status_str.startswith("4") or status_str.startswith("5") or status_str == "ERR":
                        item.setForeground(QColor("#F43F5E"))
                self.http_table.setItem(row_i, col_i, item)

    def _populate_markdown_report(self, job: ScanJobItem) -> None:
        md_text = ""
        if job.run_dir:
            md_path = Path(job.run_dir) / "report.md"
            if md_path.exists():
                try:
                    md_text = md_path.read_text(encoding="utf-8")
                except Exception:
                    pass
        if not md_text and job.report:
            try:
                md_text = render_markdown(job.report)
            except Exception as exc:
                md_text = f"# Báo cáo {job.job_id}\n\nLỗi kết xuất Markdown: {exc}"

        ai = job.ai_analysis or {}
        if ai:
            sc = ai.get("score_info") or {}
            ai_md = [
                "## 🤖 BÁO CÁO AI PHÂN TÍCH KẾT QUẢ ĐẠT ĐƯỢC (AI POST-SCAN ANALYSIS)",
                f"- **Chỉ số An ninh (Security Score):** `{sc.get('score', 85)}/100` — Hạng `{sc.get('grade', 'B')}` ({sc.get('rating', '')})",
                f"- **Engine Phân tích:** `{ai.get('engine', '')}` ({ai.get('latency_ms', 0)} ms)",
                f"- **Tóm tắt Điều hành:** {ai.get('executive_summary', '')}",
                "",
            ]
            if ai.get("llm_commentary"):
                ai_md.append("### 🧠 Nhận định từ Cụm LLM Pool")
                ai_md.append(str(ai["llm_commentary"]))
                ai_md.append("")
            if ai.get("attack_chains"):
                ai_md.append("### ⛓️ Phân tích Tương quan Rủi ro & Chuỗi Tác động")
                for c in ai["attack_chains"]:
                    ai_md.append(f"- {c}")
                ai_md.append("")
            if ai.get("remediations"):
                ai_md.append("### 🛠️ Lộ trình Khắc phục Ưu tiên & Mẫu Code Vá Lỗi")
                for r in ai["remediations"]:
                    ai_md.append(f"#### [{r.get('priority', '')}] {r.get('title', '')}")
                    ai_md.append(str(r.get("detail", "")))
                    ai_md.append("```")
                    ai_md.append(str(r.get("code", "")))
                    ai_md.append("```")
                ai_md.append("")
            ai_md.append("---\n")
            md_text = "\n".join(ai_md) + (md_text or "")

        self.report_md_edit.setPlainText(md_text or "Chưa có dữ liệu báo cáo Markdown.")

    def _copy_markdown_report(self) -> None:
        text = self.report_md_edit.toPlainText()
        QApplication.clipboard().setText(text)
        self.status_lbl.setText("📋 Đã sao chép toàn bộ Báo cáo Markdown vào Clipboard!")
        self.status_lbl.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 700;")

    # ----------------------------------------------------------------------- #
    # LLM Pool Management (/system/llm/) & Policy Intercept Methods
    # ----------------------------------------------------------------------- #

    def _refresh_llm_pool_ui(self) -> None:
        pool = load_llm_pool()
        rr_on = bool(pool.get("round_robin", True))
        self.rr_toggle_btn.setText(f"🔁 Luân chuyển tự động (Round-Robin): {'BẬT' if rr_on else 'TẮT'}")

        models = pool.get("models", [])
        self.llm_table.setRowCount(len(models))
        cards_html = ""

        for row_i, m in enumerate(models):
            is_prim = bool(m.get("is_primary"))
            st = str(m.get("status", "standby"))
            role_txt = "⭐ PRIMARY" if is_prim else "Dự phòng"
            st_txt = (
                "🟢 Đang kích hoạt (Active)"
                if st == "active"
                else (f"🔴 Đã ngắt mạch ({m.get('cooldown_remaining', 60)}s)" if st == "circuit_broken" else "🔵 Sẵn sàng (Standby)")
            )
            vals = [
                role_txt,
                str(m.get("name", "")),
                str(m.get("provider", "")),
                str(m.get("model", "")),
                f"Ưu tiên {m.get('priority', 5)}",
                f"{m.get('rps', 2)} req/s · {m.get('rpm', 30)}/min",
                f"{m.get('avg_latency_ms', 0)} ms ({m.get('success_rate', '100%')})",
                st_txt,
            ]
            for col_i, val in enumerate(vals):
                item = QTableWidgetItem(val)
                item.setData(Qt.ItemDataRole.UserRole, m.get("id"))
                if col_i == 7:
                    if st == "active":
                        item.setForeground(QColor("#10B981"))
                    elif st == "circuit_broken":
                        item.setForeground(QColor("#F43F5E"))
                    else:
                        item.setForeground(QColor("#38BDF8"))
                self.llm_table.setItem(row_i, col_i, item)

            border_col = "#38BDF8" if is_prim else ("#F43F5E" if st == "circuit_broken" else "#1E293B")
            err_line = (
                f"<div style='color:#FDA4AF; background:#3B1219; padding:5px 8px; border-radius:4px; font-size:11px; margin-top:5px;'>"
                f"⚠️ <b>Circuit Breaker:</b> {html.escape(str(m.get('last_error', '')))}</div>"
                if m.get("last_error")
                else ""
            )
            cards_html += f"""
            <div style="background:#111827; border:1.5px solid {border_col}; border-radius:8px; padding:11px 14px; margin-bottom:9px;">
                <div style="display:flex; justify-content:space-between;">
                    <span style="color:#F8FAFC; font-size:13.5px; font-weight:800;">
                        {'⭐ ' if is_prim else ''}{html.escape(str(m.get('name', '')))}
                        <span style="color:#38BDF8; font-size:11px; margin-left:6px;">[{html.escape(st_txt)}]</span>
                    </span>
                </div>
                <div style="color:#94A3B8; font-size:11.5px; margin-top:3px;">
                    🏢 <b>Provider:</b> {html.escape(str(m.get('provider', '')))} &nbsp;|&nbsp;
                    🧠 <b>Model:</b> <code>{html.escape(str(m.get('model', '')))}</code> &nbsp;|&nbsp;
                    🔗 <b>Base URL:</b> <code>{html.escape(str(m.get('base_url', '')))}</code>
                </div>
                <div style="color:#CBD5E1; font-size:11.5px; margin-top:3px;">
                    ⚡ <b>Ưu tiên:</b> {m.get('priority', 5)} &nbsp;•&nbsp;
                    ⏱️ <b>Rate Limit:</b> {m.get('rps', 2)} req/s ({m.get('rpm', 30)} req/min) &nbsp;•&nbsp;
                    📐 <b>Context:</b> {html.escape(str(m.get('context_window', '128k')))} &nbsp;•&nbsp;
                    🌡️ <b>Temp:</b> {m.get('temperature', 0.1)}
                </div>
                {err_line}
            </div>
            """

        self.llm_cards_browser.setHtml(
            f"<div style='font-family:Segoe UI,sans-serif;'>"
            f"<div style='color:#94A3B8; font-size:11.5px; margin-bottom:8px;'>"
            f"💡 <b>Cơ chế Cụm LLM Pool:</b> Khi Model chính gặp lỗi giới hạn tốc độ (HTTP 429) hoặc quá thời gian chờ, "
            f"hệ thống tự động ngắt mạch (Circuit Breaker) Model đó trong {pool.get('cooldown_seconds', 60)}s và chuyển sang Model dự phòng có độ ưu tiên cao tiếp theo."
            f"</div>{cards_html}</div>"
        )

    def _toggle_llm_round_robin(self) -> None:
        pool = load_llm_pool()
        pool["round_robin"] = not bool(pool.get("round_robin", True))
        save_llm_pool(pool)
        self._refresh_llm_pool_ui()

    def _simulate_llm_failover(self) -> None:
        pool = load_llm_pool()
        models = pool.get("models", [])
        cur_prim = next((m for m in models if m.get("is_primary")), None)
        new_prim_name = ""
        if cur_prim:
            cur_prim["is_primary"] = False
            cur_prim["status"] = "circuit_broken"
            cur_prim["cooldown_remaining"] = int(pool.get("cooldown_seconds", 60))
            cur_prim["last_error"] = "HTTP 429 Rate Limit Exceeded — Đã tự động kích hoạt Circuit Breaker & chuyển sang Model dự phòng!"
            for cand in models:
                if cand.get("id") != cur_prim.get("id") and cand.get("status") != "circuit_broken":
                    cand["is_primary"] = True
                    cand["status"] = "active"
                    new_prim_name = str(cand.get("name", ""))
                    self.ai_model_input.setText(str(cand.get("model", "")))
                    break
        save_llm_pool(pool)
        self._refresh_llm_pool_ui()
        self.status_lbl.setText(
            f"⚡ Đã giả lập ngắt mạch Model chính! Hệ thống tự động Failover sang: {new_prim_name or 'Model dự phòng'}"
        )
        self.status_lbl.setStyleSheet("color: #F59E0B; font-size: 11px; font-weight: 700;")

    def _recover_all_llm_models(self) -> None:
        pool = load_llm_pool()
        models = pool.get("models", [])
        for idx, m in enumerate(models):
            m["cooldown_remaining"] = 0
            m["last_error"] = ""
            m["is_primary"] = idx == 0
            m["status"] = "active" if idx == 0 else "standby"
        if models:
            self.ai_model_input.setText(str(models[0].get("model", "")))
        save_llm_pool(pool)
        self._refresh_llm_pool_ui()
        self.status_lbl.setText("♻️ Đã khôi phục toàn bộ mạch mô hình AI trong LLM Pool về trạng thái hoạt động tốt!")
        self.status_lbl.setStyleSheet("color: #10B981; font-size: 11px; font-weight: 700;")

    def _promote_selected_llm_model(self) -> None:
        row = self.llm_table.currentRow()
        pool = load_llm_pool()
        models = pool.get("models", [])
        if row < 0 or row >= len(models):
            return
        for idx, m in enumerate(models):
            if idx == row:
                m["is_primary"] = True
                m["status"] = "active"
                m["cooldown_remaining"] = 0
                m["last_error"] = ""
                self.ai_model_input.setText(str(m.get("model", "")))
            else:
                m["is_primary"] = False
                if m.get("status") == "active":
                    m["status"] = "standby"
        save_llm_pool(pool)
        self._refresh_llm_pool_ui()

    def _render_intercept_overview_html(self) -> str:
        return """
        <div style="font-family:'Segoe UI',sans-serif; line-height:1.5;">
            <div style="background:#111827; border:1px solid #1E293B; border-radius:8px; padding:10px 14px; margin-bottom:8px;">
                <div style="color:#38BDF8; font-weight:800; font-size:11.5px;">🛡️ CƠ CHẾ CHỐT CHẶN AN TOÀN (POLICY GUARDRAILS & MULTI-AGENT PLAYBOOK)</div>
                <div style="color:#CBD5E1; font-size:12px; margin-top:4px;">
                    • <b>ScopeGuard:</b> Ngăn chặn tuyệt đối mọi truy vấn ra ngoài tên miền/cổng mục tiêu hoặc truy cập IP nội bộ trái phép (chống SSRF).<br>
                    • <b>ArgumentGuard:</b> Xác thực kiểu dữ liệu Pydantic cho từng công cụ; AI không thể tiêm câu lệnh hệ thống hay tự chế payload phá hoại.<br>
                    • <b>ConfirmationGate & RateLimiter:</b> Kiểm soát quyền <code>ACTIVE_SCAN</code>, <code>INJECTION_PROBE</code> và giới hạn tốc độ 4 req/s.<br>
                    • <b>4 Tác tử AI (Agents):</b> <code>Recon Planner</code> · <code>Passive Posture Auditor</code> · <code>Active & Injection Prober</code> · <code>Vulnerability Retester</code>.
                </div>
            </div>
        </div>
        """

    def _populate_intercept_table(self, session: Any) -> None:
        trace_list = getattr(session, "trace", []) or []
        self.approval_table.setRowCount(len(trace_list))
        for row_i, rec in enumerate(trace_list):
            tname = str(getattr(rec, "tool", ""))
            status = str(getattr(rec, "status", "ok"))
            args = getattr(rec, "args", {}) or {}
            target_str = str(args.get("url") or args.get("page_id") or getattr(session.scope, "target", ""))
            is_active = tname in ("run_selected_active_check", "run_injection_check", "analyze_exposed_files")
            rule_str = "ConfirmationGate + ActiveCap" if is_active else "ScopeGuard + ArgumentGuard"
            dec_str = "ALLOWED (CHO PHÉP)" if status == "ok" else "BLOCKED (ĐÃ CHẶN)"
            reason_str = (
                "Hợp lệ trong phạm vi Scope & Quyền hạn"
                if status == "ok"
                else str(getattr(rec, "error", "") or "Bị từ chối bởi chính sách")
            )
            vals = [
                f"#{getattr(rec, 'step', row_i + 1)}",
                tname,
                target_str,
                rule_str,
                dec_str,
                reason_str,
            ]
            for col_i, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if col_i == 4:
                    item.setForeground(QColor("#10B981" if status == "ok" else "#F43F5E"))
                self.approval_table.setItem(row_i, col_i, item)

    def _render_welcome_dashboard_html(self) -> str:
        return """
        <div style="font-family:'Segoe UI',sans-serif; padding:10px; line-height:1.6;">
            <h3 style="color:#38BDF8; margin-top:0;">👋 Chào mừng đến với AI DAST PRO · Enterprise Edition v2.5</h3>
            <p style="color:#CBD5E1; font-size:13px;">
                Hệ thống kiểm thử xâm nhập tự động thế hệ mới tích hợp kiến trúc Zero-Trust Guardrails:
                <b>Quản lý cụm LLM Pool & Ngắt mạch tự động (/system/llm)</b>, <b>Đồ thị Chuỗi Suy Luận AI (Exploration Chain)</b>,
                <b>Kiểm tra lại lỗ hổng 1-Click (Retest)</b>, <b>Bộ lọc gói tin HTTP nâng cao</b> và <b>Hàng đợi đa nhiệm</b>.
            </p>
            <div style="background:#0F172A; border:1px solid #1E293B; border-radius:8px; padding:12px; margin-top:10px;">
                <div style="color:#F8FAFC; font-weight:bold; font-size:12px; margin-bottom:6px;">🚀 Các tính năng mới nổi bật:</div>
                <ol style="color:#94A3B8; font-size:12px; margin:0; padding-left:18px;">
                    <li><b>🧠 Quản lý LLM Pool (/system/llm):</b> Cấu hình nhiều mô hình AI (Llama 3.3, Qwen 3.8, Claude 3.7, DeepSeek), tự động ngắt mạch (Circuit Breaker) và chuyển đổi dự phòng (Auto-Failover).</li>
                    <li><b>🔄 Kiểm tra lại lỗ hổng (1-Click Retest):</b> Trong mục <b>Lỗ hổng & Retest</b>, bấm nút <b>🔄 Kiểm tra lại</b> để thẩm định trực tiếp xem lỗ hổng đã được vá hay vẫn còn tồn tại.</li>
                    <li><b>🌐 Mở Web Console:</b> Nhấn nút <b>🌐 Mở Web Console</b> trên thanh công cụ để trải nghiệm bản Web Console trực quan trên trình duyệt!</li>
                </ol>
            </div>
        </div>
        """


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("AI DAST Pro Studio")
    window = AiDastStudioWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
