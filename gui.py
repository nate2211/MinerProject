from __future__ import annotations

import asyncio
import inspect
import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional

from PyQt5.QtCore import (
    Qt,
    QThread,
    pyqtSignal,
    QTimer,
    QStandardPaths,
)
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QPlainTextEdit,
    QMessageBox,
    QSplitter,
    QTabWidget,
    QSpinBox,
    QCheckBox,
    QFileDialog,
    QSizePolicy,
    QScrollArea,
)

from miner_core import Miner
from virtualasic import resolve_resource_path

from registry import BLOCKS
import blocks_blocknet  # registers blocknet_heartbeat / blocknet_put


def app_data_dir(app_name: str = "MoneroMinerGUI") -> Path:
    base = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
    p = Path(base) / app_name
    p.mkdir(parents=True, exist_ok=True)
    return p


CFG_PATH = app_data_dir() / "miner_gui_config.json"


def _resource_roots() -> list[Path]:
    roots: list[Path] = []
    try:
        roots.append(Path.cwd())
    except Exception:
        pass
    try:
        roots.append(Path(__file__).resolve().parent)
    except Exception:
        pass
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        try:
            roots.append(Path(meipass))
        except Exception:
            pass
    exe = getattr(sys, "executable", "")
    if exe:
        try:
            roots.append(Path(exe).resolve().parent)
        except Exception:
            pass

    out: list[Path] = []
    seen = set()
    for p in roots:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        key = str(rp).lower()
        if key not in seen:
            seen.add(key)
            out.append(rp)
    return out


def _pick_existing_path(current_text: str, fallback_names: tuple[str, ...]) -> str:
    resolved = resolve_resource_path(current_text, fallback_names=fallback_names)
    if resolved and Path(resolved).exists():
        return resolved
    for root in _resource_roots():
        for name in fallback_names:
            p = root / name
            if p.exists():
                return str(p)
    return current_text or str(Path.home())


def apply_dark_theme(app: QApplication) -> None:
    app.setStyle("Fusion")

    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(24, 24, 24))
    pal.setColor(QPalette.WindowText, QColor(235, 235, 235))
    pal.setColor(QPalette.Base, QColor(16, 16, 16))
    pal.setColor(QPalette.AlternateBase, QColor(28, 28, 28))
    pal.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
    pal.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
    pal.setColor(QPalette.Text, QColor(235, 235, 235))
    pal.setColor(QPalette.Button, QColor(34, 34, 34))
    pal.setColor(QPalette.ButtonText, QColor(235, 235, 235))
    pal.setColor(QPalette.Link, QColor(110, 180, 255))
    pal.setColor(QPalette.Highlight, QColor(70, 130, 220))
    pal.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(pal)

    app.setStyleSheet(
        """
        QWidget { font-size: 12px; }
        QGroupBox {
            border: 1px solid #3a3a3a;
            border-radius: 10px;
            margin-top: 10px;
            padding: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 8px 0 8px;
            color: #dcdcdc;
            font-weight: 600;
        }
        QLineEdit, QPlainTextEdit, QSpinBox {
            border: 1px solid #404040;
            border-radius: 8px;
            padding: 7px;
            background: #101010;
            selection-background-color: #467fdc;
        }
        QPushButton {
            border: 1px solid #4a4a4a;
            border-radius: 10px;
            padding: 9px 12px;
            background: #242424;
            font-weight: 600;
        }
        QPushButton:hover { background: #2a2a2a; }
        QPushButton:pressed { background: #171717; }
        QPushButton:disabled {
            color: #7b7b7b;
            border-color: #2f2f2f;
            background: #202020;
        }
        QTabWidget::pane {
            border: 1px solid #3a3a3a;
            border-radius: 10px;
            top: -1px;
        }
        QTabBar::tab {
            background: #242424;
            border: 1px solid #3a3a3a;
            padding: 9px 14px;
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
            margin-right: 2px;
        }
        QTabBar::tab:selected { background: #161616; }
        QLabel#Pill {
            border-radius: 12px;
            padding: 5px 12px;
            font-weight: 700;
        }
        QSplitter::handle { background: #3a3a3a; }
        QSplitter::handle:horizontal { width: 10px; border-radius: 5px; }
        QSplitter::handle:vertical { height: 10px; border-radius: 5px; }
        QScrollArea {
            border: none;
            background: transparent;
        }
        """
    )


@dataclass
class MinerConfig:
    stratum: str
    wallet: str
    password: str
    threads: int
    agent: str
    randomx_lib: str

    randomx_use_large_pages: bool = True
    randomx_use_full_mem: bool = True
    randomx_use_jit: bool = True
    randomx_use_hard_aes: bool = True
    randomx_use_secure_jit: bool = False

    use_blocknet: bool = False
    blocknet_relay: str = ""
    blocknet_token: str = ""
    blocknet_id: str = "miner1"
    blocknet_key: str = ""

    use_bn_p2pool: bool = False
    use_bn_randomx: bool = False
    use_bn_p2pool_scan: bool = False
    use_bn_randomx_scan: bool = False
    use_bn_gpu_scan: bool = False
    use_bn_cpu_scan: bool = False

    use_virtualasic_scan: bool = False
    virtualasic_dll: str = ""
    virtualasic_kernel: str = ""
    virtualasic_kernel_name: str = "monero_scan"
    virtualasic_core_count: int = 0

    bn_api_relay: str = ""
    bn_api_token: str = ""
    bn_api_prefix: str = "/v1"
    bn_rx_batch: int = 64
    scan_iters: int = 1000
    submit_workers: int = 4

    use_parallel_monero_worker: bool = False
    parallel_python_dll: str = ""
    parallel_python_batch_size: int = 1024
    use_jit_worker: bool = False
    jit_batch_size: int = 1024


class MinerWorker(QThread):
    log_line = pyqtSignal(str)
    stats_updated = pyqtSignal(dict)
    state_changed = pyqtSignal(str)
    fatal_error = pyqtSignal(str)

    def __init__(self, cfg: MinerConfig) -> None:
        super().__init__()
        self.cfg = cfg
        self._miner: Optional[Miner] = None
        self._stopping = False

        self._bn_heartbeat = None
        self._bn_put = None

    def stop(self) -> None:
        self._stopping = True
        if self._miner:
            try:
                self._miner.stop()
            except Exception:
                pass

    def _setup_blocknet_reporting(self) -> None:
        if not self.cfg.use_blocknet:
            return
        if not self.cfg.blocknet_relay.strip():
            return

        self._bn_heartbeat = BLOCKS.create("blocknet_heartbeat")
        if self.cfg.blocknet_key.strip():
            self._bn_put = BLOCKS.create("blocknet_put")

    def run(self) -> None:
        try:
            self.state_changed.emit("RUNNING")

            if (not self.cfg.use_bn_randomx) and self.cfg.randomx_lib.strip():
                os.environ["RANDOMX_LIB"] = self.cfg.randomx_lib.strip()

            if self.cfg.virtualasic_dll.strip():
                os.environ["VIRTUALASIC_LIB"] = self.cfg.virtualasic_dll.strip()
            if self.cfg.virtualasic_kernel.strip():
                os.environ["VIRTUALASIC_KERNEL"] = self.cfg.virtualasic_kernel.strip()
            if self.cfg.parallel_python_dll.strip():
                os.environ["PARALLEL_PYTHON_DLL"] = self.cfg.parallel_python_dll.strip()

            self._setup_blocknet_reporting()

            stratum = (self.cfg.stratum or "").strip()
            if ":" in stratum:
                host, port_s = stratum.rsplit(":", 1)
                host = host.strip() or "127.0.0.1"
                port = int(port_s)
            else:
                host = "127.0.0.1"
                port = 3333

            miner_kwargs: Dict[str, Any] = dict(
                stratum_host=host,
                stratum_port=port,
                wallet=self.cfg.wallet.strip(),
                password=self.cfg.password,
                threads=int(self.cfg.threads),
                agent=self.cfg.agent.strip() or "py-blockminer/0.1",
                logger=self.log_line.emit,
                use_blocknet_p2pool=bool(self.cfg.use_bn_p2pool),
                blocknet_api_relay=self.cfg.bn_api_relay.strip(),
                blocknet_api_token=self.cfg.bn_api_token.strip(),
                blocknet_api_prefix=(self.cfg.bn_api_prefix.strip() or "/v1"),
                use_blocknet_randomx=bool(self.cfg.use_bn_randomx),
                randomx_batch_size=int(self.cfg.bn_rx_batch),
                submit_workers=int(self.cfg.submit_workers),
            )

            sig = inspect.signature(Miner.__init__)

            if "submit_workers" in sig.parameters:
                miner_kwargs["submit_workers"] = int(self.cfg.submit_workers)
            if "use_blocknet_p2pool_scan" in sig.parameters:
                miner_kwargs["use_blocknet_p2pool_scan"] = bool(self.cfg.use_bn_p2pool_scan)
            if "use_blocknet_randomx_scan" in sig.parameters:
                miner_kwargs["use_blocknet_randomx_scan"] = bool(self.cfg.use_bn_randomx_scan)
            if "use_blocknet_gpu_scan" in sig.parameters:
                miner_kwargs["use_blocknet_gpu_scan"] = bool(self.cfg.use_bn_gpu_scan)
            if "use_blocknet_cpu_scan" in sig.parameters:
                miner_kwargs["use_blocknet_cpu_scan"] = bool(self.cfg.use_bn_cpu_scan)
            if "use_virtualasic_scan" in sig.parameters:
                miner_kwargs["use_virtualasic_scan"] = bool(self.cfg.use_virtualasic_scan)
            if "virtualasic_dll" in sig.parameters:
                miner_kwargs["virtualasic_dll"] = self.cfg.virtualasic_dll.strip()
            if "virtualasic_kernel" in sig.parameters:
                miner_kwargs["virtualasic_kernel"] = self.cfg.virtualasic_kernel.strip()
            if "virtualasic_kernel_name" in sig.parameters:
                miner_kwargs["virtualasic_kernel_name"] = self.cfg.virtualasic_kernel_name.strip() or "monero_scan"
            if "virtualasic_core_count" in sig.parameters:
                miner_kwargs["virtualasic_core_count"] = int(self.cfg.virtualasic_core_count)
            if "scan_iters" in sig.parameters:
                miner_kwargs["scan_iters"] = int(self.cfg.scan_iters)

            if "use_parallel_monero_worker" in sig.parameters:
                miner_kwargs["use_parallel_monero_worker"] = bool(self.cfg.use_parallel_monero_worker)
            if "parallel_python_dll" in sig.parameters:
                miner_kwargs["parallel_python_dll"] = self.cfg.parallel_python_dll.strip()
            if "parallel_python_batch_size" in sig.parameters:
                miner_kwargs["parallel_python_batch_size"] = int(self.cfg.parallel_python_batch_size)
            if "use_jit_worker" in sig.parameters:
                miner_kwargs["use_jit_worker"] = bool(self.cfg.use_jit_worker)
            if "jit_batch_size" in sig.parameters:
                miner_kwargs["jit_batch_size"] = int(self.cfg.jit_batch_size)

            if "randomx_use_large_pages" in sig.parameters:
                miner_kwargs["randomx_use_large_pages"] = bool(self.cfg.randomx_use_large_pages)
            if "randomx_use_full_mem" in sig.parameters:
                miner_kwargs["randomx_use_full_mem"] = bool(self.cfg.randomx_use_full_mem)
            if "randomx_use_jit" in sig.parameters:
                miner_kwargs["randomx_use_jit"] = bool(self.cfg.randomx_use_jit)
            if "randomx_use_hard_aes" in sig.parameters:
                miner_kwargs["randomx_use_hard_aes"] = bool(self.cfg.randomx_use_hard_aes)
            if "randomx_use_secure_jit" in sig.parameters:
                miner_kwargs["randomx_use_secure_jit"] = bool(self.cfg.randomx_use_secure_jit)

            self._miner = Miner(**miner_kwargs)

            last_stats: Dict[str, Any] = {}

            def on_stats(stats: Dict[str, Any]) -> None:
                nonlocal last_stats
                last_stats = dict(stats or {})
                self.stats_updated.emit(last_stats)

                hps = float(last_stats.get("hashrate_hs") or 0.0)
                acc = int(last_stats.get("accepted") or 0)
                rej = int(last_stats.get("rejected") or 0)
                height = last_stats.get("height")
                job_id = (last_stats.get("job_id") or "")[:10]
                b_p2 = last_stats.get("backend_p2pool")
                b_rx = last_stats.get("backend_randomx")
                b_pm = bool(last_stats.get("backend_parallel_monero_worker"))
                pp_batch = last_stats.get("parallel_python_batch_size")
                b_jit = bool(last_stats.get("backend_jit_worker"))
                jit_batch = last_stats.get("jit_batch_size")

                self.log_line.emit(
                    f"[stats] {hps:,.0f} H/s | A:{acc} R:{rej} | height={height} | "
                    f"job={job_id} | p2pool={b_p2} rx={b_rx} "
                    f"parallel_worker={b_pm} jit_worker={b_jit} "
                    f"batch={pp_batch or jit_batch}"
                )

                if self._bn_heartbeat:
                    try:
                        self._bn_heartbeat.execute(
                            last_stats,
                            params={
                                "relay": self.cfg.blocknet_relay,
                                "token": self.cfg.blocknet_token,
                                "id": self.cfg.blocknet_id,
                            },
                        )
                    except Exception as e:
                        self.log_line.emit(f"[blocknet] heartbeat error: {e}")

                if self._bn_put and self.cfg.blocknet_key.strip():
                    try:
                        payload = json.dumps(last_stats).encode("utf-8")
                        self._bn_put.execute(
                            payload,
                            params={
                                "relay": self.cfg.blocknet_relay,
                                "token": self.cfg.blocknet_token,
                                "key": self.cfg.blocknet_key,
                                "mime": "application/json",
                            },
                        )
                    except Exception as e:
                        self.log_line.emit(f"[blocknet] put error: {e}")

            asyncio.run(self._miner.run(on_stats=on_stats))

        except asyncio.CancelledError:
            self.log_line.emit("[worker] cancelled during shutdown")
        except Exception:
            tb = traceback.format_exc()
            if self._stopping:
                self.log_line.emit(tb)
            else:
                self.fatal_error.emit(tb)
        finally:
            self.state_changed.emit("STOPPED")
            self._miner = None


def _mono_font(point_size: int = 10) -> QFont:
    for family in ("Consolas", "Cascadia Mono", "Courier New", "Menlo", "Monaco", "DejaVu Sans Mono"):
        font = QFont(family)
        font.setStyleHint(QFont.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(point_size)
        if font.exactMatch():
            return font

    font = QFont()
    font.setStyleHint(QFont.Monospace)
    font.setFixedPitch(True)
    font.setPointSize(point_size)
    return font


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Nate's Monero Miner (P2Pool) — BlockNet + VirtualASIC + ParallelMoneroWorker + JITWorker")
        self.worker: Optional[MinerWorker] = None
        self.started_at: float = 0.0

        self._saved_main_split_sizes: Optional[list[int]] = None
        self._log_focus_enabled: bool = False

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel("Monero Miner")
        tf = QFont()
        tf.setPointSize(16)
        tf.setBold(True)
        title.setFont(tf)

        self.pill = QLabel("STOPPED")
        self.pill.setObjectName("Pill")

        header.addWidget(title)
        header.addStretch(1)
        header.addWidget(self.pill)
        root.addLayout(header)

        self.main_split = QSplitter(Qt.Horizontal)
        self.main_split.setChildrenCollapsible(False)
        self.main_split.setHandleWidth(10)
        root.addWidget(self.main_split, 1)

        self.left_scroll = QScrollArea()
        self.left_scroll.setWidgetResizable(True)
        self.left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.left_scroll.setMinimumWidth(460)
        self.left_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.left_container = QWidget()
        self.left_scroll.setWidget(self.left_container)

        self.left_layout = QVBoxLayout(self.left_container)
        self.left_layout.setContentsMargins(0, 0, 8, 0)
        self.left_layout.setSpacing(10)

        self.main_split.addWidget(self.left_scroll)

        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        right_l.addWidget(self.tabs)
        self.main_split.addWidget(right)

        self.main_split.setStretchFactor(0, 1)
        self.main_split.setStretchFactor(1, 2)

        gb_conn = QGroupBox("Mining (P2Pool Stratum)")
        fl = QFormLayout(gb_conn)

        self.ed_stratum = QLineEdit("127.0.0.1:3333")
        self.ed_wallet = QLineEdit("")
        self.ed_pass = QLineEdit("x")
        self.ed_agent = QLineEdit("py-blockminer/0.1")

        fl.addRow("Stratum (host:port)", self.ed_stratum)
        fl.addRow("Wallet address", self.ed_wallet)
        fl.addRow("Password", self.ed_pass)
        fl.addRow("Agent", self.ed_agent)

        self.left_layout.addWidget(gb_conn)

        gb_perf = QGroupBox("Performance")
        pfl = QFormLayout(gb_perf)

        self.sp_threads = QSpinBox()
        self.sp_threads.setRange(1, 256)
        self.sp_threads.setValue(4)

        self.ed_randomx = QLineEdit("")
        self.btn_browse_randomx = QPushButton("Browse…")
        self.btn_browse_randomx.clicked.connect(self._browse_randomx)

        pfl.addRow("Threads", self.sp_threads)
        pfl.addRow("RandomX lib (local only)", self._hbox(self.ed_randomx, self.btn_browse_randomx))

        self.left_layout.addWidget(gb_perf)

        gb_rx_flags = QGroupBox("RandomX Flags (local only)")
        rxfl = QFormLayout(gb_rx_flags)

        self.cb_rx_large_pages = QCheckBox("Enable LARGE_PAGES")
        self.cb_rx_large_pages.setChecked(True)
        self.cb_rx_large_pages.setToolTip("Requests huge/large page allocation when available.")

        self.cb_rx_full_mem = QCheckBox("Enable FULL_MEM")
        self.cb_rx_full_mem.setChecked(True)
        self.cb_rx_full_mem.setToolTip("Use full dataset memory mode.")

        self.cb_rx_jit = QCheckBox("Enable JIT")
        self.cb_rx_jit.setChecked(True)
        self.cb_rx_jit.setToolTip("Enable RandomX JIT compilation.")

        self.cb_rx_hard_aes = QCheckBox("Enable HARD_AES")
        self.cb_rx_hard_aes.setChecked(True)
        self.cb_rx_hard_aes.setToolTip("Use hardware AES instructions when available.")

        self.cb_rx_secure_jit = QCheckBox("Enable SECURE_JIT")
        self.cb_rx_secure_jit.setChecked(False)
        self.cb_rx_secure_jit.setToolTip("Enable secure JIT mode.")

        rx_info = QLabel(
            "These apply only to local RandomX usage: normal local mining, JITWorker, "
            "ParallelMoneroWorker, and VirtualASIC CPU verification. "
            "They do not affect remote BlockNet hashing/scan modes."
        )
        rx_info.setWordWrap(True)
        rx_info.setStyleSheet("color:#bcbcbc;")

        rxfl.addRow(self.cb_rx_large_pages)
        rxfl.addRow(self.cb_rx_full_mem)
        rxfl.addRow(self.cb_rx_jit)
        rxfl.addRow(self.cb_rx_hard_aes)
        rxfl.addRow(self.cb_rx_secure_jit)
        rxfl.addRow(rx_info)

        self.left_layout.addWidget(gb_rx_flags)

        gb_bn = QGroupBox("BlockNet Reporting (optional)")
        bfl = QFormLayout(gb_bn)

        self.cb_bn = QCheckBox("Enable BlockNet heartbeat + stats PUT")
        self.cb_bn.setChecked(False)

        self.ed_bn_relay = QLineEdit("127.0.0.1:38887")
        self.ed_bn_token = QLineEdit("")
        self.ed_bn_token.setEchoMode(QLineEdit.Password)
        self.ed_bn_id = QLineEdit("miner1")
        self.ed_bn_key = QLineEdit("miner/stats")

        bfl.addRow(self.cb_bn)
        bfl.addRow("Relay (host:port)", self.ed_bn_relay)
        bfl.addRow("Token", self.ed_bn_token)
        bfl.addRow("Heartbeat ID", self.ed_bn_id)
        bfl.addRow("PUT key", self.ed_bn_key)

        self.left_layout.addWidget(gb_bn)

        gb_bn_mine = QGroupBox("Mining Backends / Scan Modes")
        mfl = QFormLayout(gb_bn_mine)

        self.cb_bn_gpu_scan = QCheckBox("Use BlockNet GPU scan (/gpu/scan) — server-side GPU scanning")
        self.cb_bn_cpu_scan = QCheckBox("Use BlockNet CPU scan (/cpu/scan) — server-side CPU scanning")
        self.cb_bn_p2pool = QCheckBox("Use BlockNet P2Pool API (instead of direct Stratum TCP)")
        self.cb_bn_randomx = QCheckBox("Use BlockNet RandomX API (remote hashing)")
        self.cb_bn_p2pool_scan = QCheckBox("Use BlockNet P2Pool scan (/p2pool/scan) — server-side scanning")
        self.cb_bn_randomx_scan = QCheckBox("Use BlockNet RandomX scan (/randomx/scan) — server-side scanning")
        self.cb_vasic_scan = QCheckBox("Use VirtualASIC local scan — loads VirtualASIC.dll and a compatible scan kernel")
        self.cb_parallel_monero_worker = QCheckBox(
            "Use ParallelMoneroWorker — local RandomX hashing through ParallelPython callback exports"
        )
        self.cb_jit_worker = QCheckBox(
            "Use JITWorker — local RandomX hashing through PythonJIT/JITWorker"
        )

        self.sp_jit_batch_size = QSpinBox()
        self.sp_jit_batch_size.setRange(1, 1_000_000)
        self.sp_jit_batch_size.setValue(1024)

        self.ed_bn_api_relay = QLineEdit("127.0.0.1:38888")
        self.ed_bn_api_token = QLineEdit("")
        self.ed_bn_api_token.setEchoMode(QLineEdit.Password)
        self.ed_bn_api_prefix = QLineEdit("/v1")

        self.ed_vasic_dll = QLineEdit("")
        self.btn_browse_vasic_dll = QPushButton("Browse…")
        self.btn_browse_vasic_dll.clicked.connect(self._browse_virtualasic_dll)

        self.ed_vasic_kernel = QLineEdit("")
        self.btn_browse_vasic_kernel = QPushButton("Browse…")
        self.btn_browse_vasic_kernel.clicked.connect(self._browse_virtualasic_kernel)

        self.ed_vasic_kernel_name = QLineEdit("monero_scan")

        self.ed_parallel_python_dll = QLineEdit("")
        self.btn_browse_parallel_python_dll = QPushButton("Browse…")
        self.btn_browse_parallel_python_dll.clicked.connect(self._browse_parallel_python_dll)

        self.sp_parallel_python_batch_size = QSpinBox()
        self.sp_parallel_python_batch_size.setRange(1, 1_000_000)
        self.sp_parallel_python_batch_size.setValue(1024)

        self.sp_vasic_core_count = QSpinBox()
        self.sp_vasic_core_count.setRange(0, 1024)
        self.sp_vasic_core_count.setValue(0)
        self.sp_vasic_core_count.setToolTip("0 lets VirtualASIC choose its preferred local size.")

        self.sp_bn_rx_batch = QSpinBox()
        self.sp_bn_rx_batch.setRange(1, 4096)
        self.sp_bn_rx_batch.setValue(64)

        self.sp_submit_workers = QSpinBox()
        self.sp_submit_workers.setRange(1, 32)
        self.sp_submit_workers.setValue(4)

        self.sp_scan_iters = QSpinBox()
        self.sp_scan_iters.setRange(1, 10_000_000)
        self.sp_scan_iters.setSingleStep(100)
        self.sp_scan_iters.setValue(1000)

        mfl.addRow(self.cb_bn_gpu_scan)
        mfl.addRow(self.cb_bn_cpu_scan)
        mfl.addRow(self.cb_bn_p2pool)
        mfl.addRow(self.cb_bn_randomx)
        mfl.addRow(self.cb_bn_p2pool_scan)
        mfl.addRow(self.cb_bn_randomx_scan)
        mfl.addRow(self.cb_vasic_scan)
        mfl.addRow(self.cb_parallel_monero_worker)
        mfl.addRow(self.cb_jit_worker)
        mfl.addRow("JIT batch size", self.sp_jit_batch_size)
        mfl.addRow("ParallelPython DLL", self._hbox(self.ed_parallel_python_dll, self.btn_browse_parallel_python_dll))
        mfl.addRow("ParallelPython batch size", self.sp_parallel_python_batch_size)
        mfl.addRow("API Relay (host:port)", self.ed_bn_api_relay)
        mfl.addRow("API Token", self.ed_bn_api_token)
        mfl.addRow("API Prefix", self.ed_bn_api_prefix)
        mfl.addRow("VirtualASIC DLL", self._hbox(self.ed_vasic_dll, self.btn_browse_vasic_dll))
        mfl.addRow("VirtualASIC kernel", self._hbox(self.ed_vasic_kernel, self.btn_browse_vasic_kernel))
        mfl.addRow("VirtualASIC kernel name", self.ed_vasic_kernel_name)
        mfl.addRow("VirtualASIC core count", self.sp_vasic_core_count)
        mfl.addRow("RandomX batch size", self.sp_bn_rx_batch)
        mfl.addRow("Share workers", self.sp_submit_workers)
        mfl.addRow("Scan iterations", self.sp_scan_iters)

        info = QLabel(
            "Only one scan mode should be enabled at a time. "
            "ParallelMoneroWorker uses local RandomX hashing through the ParallelPython callback/export path. "
            "VirtualASIC expects a compatible kernel that writes result records as "
            "[nonce_u32 little-endian][32-byte hash] and a count buffer."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#bcbcbc;")
        mfl.addRow(info)

        self.left_layout.addWidget(gb_bn_mine)

        self.cb_bn_p2pool.toggled.connect(self._sync_scan_checks)
        self.cb_bn_randomx.toggled.connect(self._sync_scan_checks)
        self.cb_bn_p2pool_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_bn_randomx_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_bn_gpu_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_bn_cpu_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_vasic_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_parallel_monero_worker.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_jit_worker.toggled.connect(self._sync_scan_mode_exclusive)
        self._sync_scan_checks()

        gb_ctrl = QGroupBox("Controls")
        cl = QVBoxLayout(gb_ctrl)

        btn_row = QHBoxLayout()
        self.btn_start = QPushButton("Start Mining")
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setDisabled(True)

        self.btn_start.clicked.connect(self._start)
        self.btn_stop.clicked.connect(self._stop)
        self._set_running(False)

        btn_row.addWidget(self.btn_start)
        btn_row.addWidget(self.btn_stop)
        cl.addLayout(btn_row)

        btn_row2 = QHBoxLayout()
        self.btn_save = QPushButton("Save Config")
        self.btn_load = QPushButton("Load Config")
        self.btn_clear = QPushButton("Clear Log")

        self.btn_save.clicked.connect(self._save_cfg)
        self.btn_load.clicked.connect(self._load_cfg)
        self.btn_clear.clicked.connect(lambda: self.txt_log.setPlainText(""))

        btn_row2.addWidget(self.btn_save)
        btn_row2.addWidget(self.btn_load)
        btn_row2.addWidget(self.btn_clear)
        cl.addLayout(btn_row2)

        self.left_layout.addWidget(gb_ctrl)
        self.left_layout.addStretch(1)

        dash = QWidget()
        dl = QVBoxLayout(dash)
        dl.setContentsMargins(10, 10, 10, 10)
        dl.setSpacing(10)

        self.lbl_hashrate = QLabel("0 H/s")
        hf = QFont()
        hf.setPointSize(28)
        hf.setBold(True)
        self.lbl_hashrate.setFont(hf)

        self.lbl_sub = QLabel("Accepted: 0    Rejected: 0    Height: —    Threads: —")
        sf = QFont()
        sf.setPointSize(12)
        self.lbl_sub.setFont(sf)

        self.lbl_uptime = QLabel("Uptime: 00:00:00")
        self.lbl_uptime.setStyleSheet("color:#cfcfcf;")

        dl.addWidget(self.lbl_hashrate)
        dl.addWidget(self.lbl_sub)
        dl.addWidget(self.lbl_uptime)
        dl.addStretch(1)

        self.tabs.addTab(dash, "Dashboard")

        log = QWidget()
        ll = QVBoxLayout(log)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(0)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(_mono_font())
        ll.addWidget(self.txt_log)
        self.tabs.addTab(log, "Log")

        raw = QWidget()
        rl = QVBoxLayout(raw)
        rl.setContentsMargins(10, 10, 10, 10)
        self.txt_raw = QPlainTextEdit()
        self.txt_raw.setReadOnly(True)
        self.txt_raw.setFont(_mono_font())
        rl.addWidget(self.txt_raw)
        self.tabs.addTab(raw, "Raw Stats")

        self.uptime_timer = QTimer(self)
        self.uptime_timer.setInterval(500)
        self.uptime_timer.timeout.connect(self._tick_uptime)

        self.main_split.setSizes([620, 900])

        self._load_cfg()
        self._autofill_resource_guesses()
        self.statusBar().showMessage("Ready")

    def _autofill_resource_guesses(self) -> None:
        if not self.ed_vasic_dll.text().strip():
            guess = resolve_resource_path("", fallback_names=("VirtualASIC.dll", "virtualasic.dll"))
            if guess:
                self.ed_vasic_dll.setText(guess)
        if not self.ed_vasic_kernel.text().strip():
            guess = resolve_resource_path(
                "",
                fallback_names=("monero_scan.cl", "virtualasic_monero_scan.cl", "randomx_scan.cl"),
            )
            if guess:
                self.ed_vasic_kernel.setText(guess)
        if not self.ed_parallel_python_dll.text().strip():
            guess = resolve_resource_path("", fallback_names=("ParallelPython.dll", "parallelpython.dll"))
            if guess:
                self.ed_parallel_python_dll.setText(guess)

    def _sync_scan_mode_exclusive(self) -> None:
        sender = self.sender()
        if not isinstance(sender, QCheckBox):
            return
        if not sender.isChecked():
            return

        for cb in (
            self.cb_bn_p2pool_scan,
            self.cb_bn_randomx_scan,
            self.cb_bn_gpu_scan,
            self.cb_bn_cpu_scan,
            self.cb_vasic_scan,
            self.cb_parallel_monero_worker,
            self.cb_jit_worker,
        ):
            if cb is sender:
                continue
            old = cb.blockSignals(True)
            cb.setChecked(False)
            cb.blockSignals(old)

    def _sync_scan_checks(self) -> None:
        p2 = bool(self.cb_bn_p2pool.isChecked())
        rx = bool(self.cb_bn_randomx.isChecked())

        self.cb_bn_p2pool_scan.setEnabled(p2)
        if not p2:
            self.cb_bn_p2pool_scan.setChecked(False)

        self.cb_bn_randomx_scan.setEnabled(rx)
        if not rx:
            self.cb_bn_randomx_scan.setChecked(False)

        self.cb_bn_gpu_scan.setEnabled(True)
        self.cb_bn_cpu_scan.setEnabled(True)
        self.cb_vasic_scan.setEnabled(True)
        self.cb_parallel_monero_worker.setEnabled(True)
        self.cb_jit_worker.setEnabled(True)

    def _on_tab_changed(self, idx: int) -> None:
        tab_name = self.tabs.tabText(idx)
        self._set_log_focus(tab_name == "Log")

    def _set_log_focus(self, enable: bool) -> None:
        if enable and not self._log_focus_enabled:
            self._saved_main_split_sizes = self.main_split.sizes()
            self.left_scroll.setVisible(False)
            self.main_split.setSizes([0, max(1, self.width())])
            self._log_focus_enabled = True
        elif (not enable) and self._log_focus_enabled:
            self.left_scroll.setVisible(True)
            if self._saved_main_split_sizes:
                self.main_split.setSizes(self._saved_main_split_sizes)
            else:
                self.main_split.setSizes([620, 900])
            self._log_focus_enabled = False

    @staticmethod
    def _hbox(*widgets: QWidget) -> QWidget:
        w = QWidget()
        l = QHBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(8)
        for x in widgets:
            l.addWidget(x)
        return w

    def _append_log(self, s: str) -> None:
        s = (s or "").replace("\r\n", "\n").replace("\r", "\n").strip()
        if not s:
            return
        self.txt_log.appendPlainText(s)

        max_blocks = 5000
        doc = self.txt_log.document()
        if doc.blockCount() > max_blocks:
            cur = self.txt_log.textCursor()
            cur.movePosition(cur.Start)
            for _ in range(doc.blockCount() - max_blocks):
                cur.select(cur.LineUnderCursor)
                cur.removeSelectedText()
                cur.deleteChar()

    def _set_running(self, running: bool) -> None:
        if running:
            self.pill.setText("RUNNING")
            self.pill.setStyleSheet("background:#143d27; color:#eaffea;")
        else:
            self.pill.setText("STOPPED")
            self.pill.setStyleSheet("background:#4a1f1f; color:#ffecec;")

        self.btn_start.setDisabled(running)
        self.btn_stop.setDisabled(not running)

    def _browse_randomx(self) -> None:
        start = _pick_existing_path(self.ed_randomx.text().strip(), ("randomx-dll.dll", "randomx.dll"))
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select RandomX library",
            start,
            "RandomX Library (*.dll *.so *.dylib);;All files (*.*)",
        )
        if path:
            self.ed_randomx.setText(path)

    def _browse_virtualasic_dll(self) -> None:
        start = _pick_existing_path(self.ed_vasic_dll.text().strip(), ("VirtualASIC.dll", "virtualasic.dll"))
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select VirtualASIC DLL",
            start,
            "VirtualASIC (*.dll *.so *.dylib);;All files (*.*)",
        )
        if path:
            self.ed_vasic_dll.setText(path)

    def _browse_virtualasic_kernel(self) -> None:
        start = _pick_existing_path(
            self.ed_vasic_kernel.text().strip(),
            ("monero_scan.cl", "virtualasic_monero_scan.cl", "randomx_scan.cl"),
        )
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select VirtualASIC kernel",
            start,
            "OpenCL Kernel (*.cl *.txt);;All files (*.*)",
        )
        if path:
            self.ed_vasic_kernel.setText(path)

    def _browse_parallel_python_dll(self) -> None:
        start = _pick_existing_path(
            self.ed_parallel_python_dll.text().strip(),
            ("ParallelPython.dll", "parallelpython.dll"),
        )
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select ParallelPython DLL",
            start,
            "DLL (*.dll *.so *.dylib);;All files (*.*)",
        )
        if path:
            self.ed_parallel_python_dll.setText(path)

    def _tick_uptime(self) -> None:
        if not self.started_at:
            self.lbl_uptime.setText("Uptime: 00:00:00")
            return
        elapsed = max(0, int(time.time() - self.started_at))
        h = elapsed // 3600
        m = (elapsed % 3600) // 60
        s = elapsed % 60
        self.lbl_uptime.setText(f"Uptime: {h:02d}:{m:02d}:{s:02d}")

    def _on_stats(self, stats: Dict[str, Any]) -> None:
        hps = float(stats.get("hashrate_hs") or 0.0)
        acc = int(stats.get("accepted") or 0)
        rej = int(stats.get("rejected") or 0)
        height = stats.get("height")
        threads = stats.get("threads")
        self.lbl_hashrate.setText(f"{hps:,.0f} H/s")
        self.lbl_sub.setText(f"Accepted: {acc}    Rejected: {rej}    Height: {height}    Threads: {threads}")
        self.txt_raw.setPlainText(json.dumps(stats, indent=2, sort_keys=True))

    def _on_state(self, s: str) -> None:
        if s == "RUNNING":
            self._set_running(True)
        else:
            self._set_running(False)
            self.started_at = 0.0
            self.uptime_timer.stop()
            self._tick_uptime()
            self._append_log("[gui] stopped")

    def _on_fatal(self, tb: str) -> None:
        self._set_running(False)
        self.started_at = 0.0
        self.uptime_timer.stop()
        self._tick_uptime()
        self._append_log(tb)
        QMessageBox.critical(self, "Miner Error", tb)

    def _uses_local_randomx(self, cfg: MinerConfig) -> bool:
        if cfg.use_virtualasic_scan or cfg.use_parallel_monero_worker or cfg.use_jit_worker:
            return True

        if cfg.use_bn_randomx:
            return False
        if cfg.use_bn_randomx_scan:
            return False
        if cfg.use_bn_gpu_scan:
            return False
        if cfg.use_bn_cpu_scan:
            return False
        if cfg.use_bn_p2pool_scan:
            return False

        return True

    def _randomx_flags_summary(self, cfg: MinerConfig) -> str:
        enabled = []
        if cfg.randomx_use_large_pages:
            enabled.append("LARGE_PAGES")
        if cfg.randomx_use_full_mem:
            enabled.append("FULL_MEM")
        if cfg.randomx_use_jit:
            enabled.append("JIT")
        if cfg.randomx_use_hard_aes:
            enabled.append("HARD_AES")
        if cfg.randomx_use_secure_jit:
            enabled.append("SECURE_JIT")
        return ", ".join(enabled) if enabled else "DEFAULT/NONE"

    def _build_cfg(self) -> MinerConfig:
        stratum = self.ed_stratum.text().strip()
        wallet = self.ed_wallet.text().strip()
        password = self.ed_pass.text()
        threads = int(self.sp_threads.value())
        agent = self.ed_agent.text().strip() or "py-blockminer/0.1"
        randomx_lib = self.ed_randomx.text().strip()

        use_bn_p2pool = bool(self.cb_bn_p2pool.isChecked())
        use_bn_randomx = bool(self.cb_bn_randomx.isChecked())
        use_bn_gpu_scan = bool(self.cb_bn_gpu_scan.isChecked())
        use_bn_cpu_scan = bool(self.cb_bn_cpu_scan.isChecked())
        use_bn_p2pool_scan = bool(self.cb_bn_p2pool_scan.isChecked())
        use_bn_randomx_scan = bool(self.cb_bn_randomx_scan.isChecked())
        use_virtualasic_scan = bool(self.cb_vasic_scan.isChecked())
        use_parallel_monero_worker = bool(self.cb_parallel_monero_worker.isChecked())
        use_jit_worker = bool(self.cb_jit_worker.isChecked())
        jit_batch_size = int(self.sp_jit_batch_size.value())
        bn_api_relay = self.ed_bn_api_relay.text().strip()
        submit_workers = int(self.sp_submit_workers.value())
        scan_iters = int(self.sp_scan_iters.value())

        vasic_dll = self.ed_vasic_dll.text().strip()
        vasic_kernel = self.ed_vasic_kernel.text().strip()
        vasic_kernel_name = self.ed_vasic_kernel_name.text().strip() or "monero_scan"

        parallel_python_dll = self.ed_parallel_python_dll.text().strip()
        parallel_python_batch_size = int(self.sp_parallel_python_batch_size.value())

        if use_virtualasic_scan:
            if not vasic_dll:
                QMessageBox.warning(self, "Missing VirtualASIC DLL", "Please choose a VirtualASIC DLL path.")
                raise ValueError("missing VirtualASIC DLL")
            if not vasic_kernel:
                QMessageBox.warning(self, "Missing VirtualASIC kernel", "Please choose a VirtualASIC kernel path.")
                raise ValueError("missing VirtualASIC kernel")
            if threads > 1:
                self._append_log(
                    "[gui] warning: VirtualASIC with threads > 1 creates one engine per worker and may reduce GPU efficiency."
                )

        use_bn_reporting = bool(self.cb_bn.isChecked())

        return MinerConfig(
            stratum=stratum,
            wallet=wallet,
            password=password,
            threads=threads,
            agent=agent,
            randomx_lib=randomx_lib,
            randomx_use_large_pages=bool(self.cb_rx_large_pages.isChecked()),
            randomx_use_full_mem=bool(self.cb_rx_full_mem.isChecked()),
            randomx_use_jit=bool(self.cb_rx_jit.isChecked()),
            randomx_use_hard_aes=bool(self.cb_rx_hard_aes.isChecked()),
            randomx_use_secure_jit=bool(self.cb_rx_secure_jit.isChecked()),
            use_blocknet=use_bn_reporting,
            blocknet_relay=self.ed_bn_relay.text().strip(),
            blocknet_token=self.ed_bn_token.text().strip(),
            blocknet_id=self.ed_bn_id.text().strip() or "miner1",
            blocknet_key=self.ed_bn_key.text().strip(),
            use_bn_p2pool=use_bn_p2pool,
            use_bn_randomx=use_bn_randomx,
            use_bn_gpu_scan=use_bn_gpu_scan,
            use_bn_cpu_scan=use_bn_cpu_scan,
            use_bn_p2pool_scan=use_bn_p2pool_scan,
            use_bn_randomx_scan=use_bn_randomx_scan,
            use_virtualasic_scan=use_virtualasic_scan,
            virtualasic_dll=vasic_dll,
            virtualasic_kernel=vasic_kernel,
            virtualasic_kernel_name=vasic_kernel_name,
            virtualasic_core_count=int(self.sp_vasic_core_count.value()),
            submit_workers=submit_workers,
            bn_api_relay=bn_api_relay,
            bn_api_token=self.ed_bn_api_token.text().strip(),
            bn_api_prefix=self.ed_bn_api_prefix.text().strip() or "/v1",
            bn_rx_batch=int(self.sp_bn_rx_batch.value()),
            scan_iters=scan_iters,
            use_parallel_monero_worker=use_parallel_monero_worker,
            parallel_python_dll=parallel_python_dll,
            parallel_python_batch_size=parallel_python_batch_size,
            use_jit_worker=use_jit_worker,
            jit_batch_size=jit_batch_size,
        )

    def _start(self) -> None:
        try:
            cfg = self._build_cfg()
        except Exception as e:
            self._append_log(f"[gui] start aborted: {e}")
            return

        self._save_cfg()

        self.txt_log.appendPlainText("[gui] starting miner…")

        if self._uses_local_randomx(cfg):
            self.txt_log.appendPlainText(
                f"[gui] local RandomX flags: {self._randomx_flags_summary(cfg)}"
            )

        if cfg.use_virtualasic_scan:
            self.txt_log.appendPlainText(
                f"[gui] virtualasic dll={resolve_resource_path(cfg.virtualasic_dll, fallback_names=('VirtualASIC.dll', 'virtualasic.dll'))} "
                f"kernel={resolve_resource_path(cfg.virtualasic_kernel, fallback_names=('monero_scan.cl', 'virtualasic_monero_scan.cl', 'randomx_scan.cl'))} "
                f"kernel_name={cfg.virtualasic_kernel_name}"
            )

        if cfg.use_parallel_monero_worker:
            self.txt_log.appendPlainText(
                f"[gui] parallel monero worker enabled: "
                f"threads={cfg.threads} "
                f"dll={cfg.parallel_python_dll or 'auto'} "
                f"batch_size={cfg.parallel_python_batch_size}"
            )

        self._set_running(True)
        self.started_at = time.time()
        self.uptime_timer.start()

        self.worker = MinerWorker(cfg)
        self.worker.log_line.connect(self._append_log)
        self.worker.stats_updated.connect(self._on_stats)
        self.worker.state_changed.connect(self._on_state)
        self.worker.fatal_error.connect(self._on_fatal)
        self.worker.start()

    def _stop(self) -> None:
        if self.worker and self.worker.isRunning():
            self._append_log("[gui] stopping…")
            self.btn_stop.setDisabled(True)
            self.btn_start.setDisabled(True)
            self.worker.stop()
        else:
            self._set_running(False)

    def _save_cfg(self) -> None:
        try:
            cfg = self._build_cfg()
        except Exception:
            cfg = None

        data: Dict[str, Any] = {}
        if cfg is not None:
            data = asdict(cfg)
        else:
            data = {
                "stratum": self.ed_stratum.text(),
                "wallet": self.ed_wallet.text(),
                "password": self.ed_pass.text(),
                "threads": int(self.sp_threads.value()),
                "agent": self.ed_agent.text(),
                "randomx_lib": self.ed_randomx.text(),
                "randomx_use_large_pages": bool(self.cb_rx_large_pages.isChecked()),
                "randomx_use_full_mem": bool(self.cb_rx_full_mem.isChecked()),
                "randomx_use_jit": bool(self.cb_rx_jit.isChecked()),
                "randomx_use_hard_aes": bool(self.cb_rx_hard_aes.isChecked()),
                "randomx_use_secure_jit": bool(self.cb_rx_secure_jit.isChecked()),
                "use_blocknet": bool(self.cb_bn.isChecked()),
                "blocknet_relay": self.ed_bn_relay.text(),
                "blocknet_token": self.ed_bn_token.text(),
                "blocknet_id": self.ed_bn_id.text(),
                "blocknet_key": self.ed_bn_key.text(),
                "use_bn_p2pool": bool(self.cb_bn_p2pool.isChecked()),
                "use_bn_randomx": bool(self.cb_bn_randomx.isChecked()),
                "use_bn_p2pool_scan": bool(self.cb_bn_p2pool_scan.isChecked()),
                "use_bn_randomx_scan": bool(self.cb_bn_randomx_scan.isChecked()),
                "use_bn_gpu_scan": bool(self.cb_bn_gpu_scan.isChecked()),
                "use_bn_cpu_scan": bool(self.cb_bn_cpu_scan.isChecked()),
                "use_virtualasic_scan": bool(self.cb_vasic_scan.isChecked()),
                "virtualasic_dll": self.ed_vasic_dll.text(),
                "virtualasic_kernel": self.ed_vasic_kernel.text(),
                "virtualasic_kernel_name": self.ed_vasic_kernel_name.text(),
                "virtualasic_core_count": int(self.sp_vasic_core_count.value()),
                "bn_api_relay": self.ed_bn_api_relay.text(),
                "bn_api_token": self.ed_bn_api_token.text(),
                "bn_api_prefix": self.ed_bn_api_prefix.text(),
                "bn_rx_batch": int(self.sp_bn_rx_batch.value()),
                "scan_iters": int(self.sp_scan_iters.value()),
                "submit_workers": int(self.sp_submit_workers.value()),
                "use_parallel_monero_worker": bool(self.cb_parallel_monero_worker.isChecked()),
                "parallel_python_dll": self.ed_parallel_python_dll.text(),
                "parallel_python_batch_size": int(self.sp_parallel_python_batch_size.value()),
                "use_jit_worker": bool(self.cb_jit_worker.isChecked()),
                "jit_batch_size": int(self.sp_jit_batch_size.value()),
            }

        try:
            CFG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.statusBar().showMessage(f"Saved config: {CFG_PATH}", 4000)
        except Exception as e:
            self._append_log(f"[gui] save config failed: {e}")

    def _load_cfg(self) -> None:
        if not CFG_PATH.exists():
            return

        try:
            data = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            self._append_log(f"[gui] load config failed: {e}")
            return

        self.ed_stratum.setText(str(data.get("stratum", self.ed_stratum.text())))
        self.ed_wallet.setText(str(data.get("wallet", self.ed_wallet.text())))
        self.ed_pass.setText(str(data.get("password", self.ed_pass.text())))
        self.sp_threads.setValue(int(data.get("threads", self.sp_threads.value())))
        self.ed_agent.setText(str(data.get("agent", self.ed_agent.text())))
        self.ed_randomx.setText(str(data.get("randomx_lib", self.ed_randomx.text())))

        self.cb_rx_large_pages.setChecked(bool(data.get("randomx_use_large_pages", True)))
        self.cb_rx_full_mem.setChecked(bool(data.get("randomx_use_full_mem", True)))
        self.cb_rx_jit.setChecked(bool(data.get("randomx_use_jit", True)))
        self.cb_rx_hard_aes.setChecked(bool(data.get("randomx_use_hard_aes", True)))
        self.cb_rx_secure_jit.setChecked(bool(data.get("randomx_use_secure_jit", False)))

        self.cb_bn.setChecked(bool(data.get("use_blocknet", self.cb_bn.isChecked())))
        self.ed_bn_relay.setText(str(data.get("blocknet_relay", self.ed_bn_relay.text())))
        self.ed_bn_token.setText(str(data.get("blocknet_token", self.ed_bn_token.text())))
        self.ed_bn_id.setText(str(data.get("blocknet_id", self.ed_bn_id.text())))
        self.ed_bn_key.setText(str(data.get("blocknet_key", self.ed_bn_key.text())))

        self.cb_bn_p2pool.setChecked(bool(data.get("use_bn_p2pool", self.cb_bn_p2pool.isChecked())))
        self.cb_bn_randomx.setChecked(bool(data.get("use_bn_randomx", self.cb_bn_randomx.isChecked())))
        self.cb_bn_p2pool_scan.setChecked(bool(data.get("use_bn_p2pool_scan", self.cb_bn_p2pool_scan.isChecked())))
        self.cb_bn_randomx_scan.setChecked(bool(data.get("use_bn_randomx_scan", self.cb_bn_randomx_scan.isChecked())))
        self.cb_bn_gpu_scan.setChecked(bool(data.get("use_bn_gpu_scan", self.cb_bn_gpu_scan.isChecked())))
        self.cb_bn_cpu_scan.setChecked(bool(data.get("use_bn_cpu_scan", self.cb_bn_cpu_scan.isChecked())))

        self.cb_vasic_scan.setChecked(bool(data.get("use_virtualasic_scan", self.cb_vasic_scan.isChecked())))
        self.ed_vasic_dll.setText(str(data.get("virtualasic_dll", self.ed_vasic_dll.text())))
        self.ed_vasic_kernel.setText(str(data.get("virtualasic_kernel", self.ed_vasic_kernel.text())))
        self.ed_vasic_kernel_name.setText(str(data.get("virtualasic_kernel_name", self.ed_vasic_kernel_name.text())))
        self.sp_vasic_core_count.setValue(int(data.get("virtualasic_core_count", self.sp_vasic_core_count.value())))

        self.ed_bn_api_relay.setText(str(data.get("bn_api_relay", self.ed_bn_api_relay.text())))
        self.ed_bn_api_token.setText(str(data.get("bn_api_token", self.ed_bn_api_token.text())))
        self.ed_bn_api_prefix.setText(str(data.get("bn_api_prefix", self.ed_bn_api_prefix.text())))
        self.sp_bn_rx_batch.setValue(int(data.get("bn_rx_batch", self.sp_bn_rx_batch.value())))
        self.sp_scan_iters.setValue(int(data.get("scan_iters", self.sp_scan_iters.value())))
        self.sp_submit_workers.setValue(int(data.get("submit_workers", self.sp_submit_workers.value())))

        self.cb_parallel_monero_worker.setChecked(bool(data.get("use_parallel_monero_worker", False)))
        self.ed_parallel_python_dll.setText(str(data.get("parallel_python_dll", self.ed_parallel_python_dll.text())))
        self.sp_parallel_python_batch_size.setValue(
            int(data.get("parallel_python_batch_size", self.sp_parallel_python_batch_size.value()))
        )
        self.cb_jit_worker.setChecked(bool(data.get("use_jit_worker", False)))
        self.sp_jit_batch_size.setValue(int(data.get("jit_batch_size", self.sp_jit_batch_size.value())))
        self._sync_scan_checks()

    def closeEvent(self, event) -> None:
        try:
            self._save_cfg()
        except Exception:
            pass

        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)

        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    apply_dark_theme(app)
    w = MainWindow()
    w.resize(1450, 900)
    w.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())