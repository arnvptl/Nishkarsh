# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build specification for SAT-SA.

Produces a single-file executable: satsa.exe (Windows) / satsa (Linux).
The binary is self-contained and air-gap deployable.

Build:
    pip install pyinstaller==6.11.1
    pyinstaller satsa.spec

Notes:
  - datasketch (MinHash/LSH) is a pure-Python package — bundled automatically.
  - diptest is a compiled C extension — if import fails, G3 falls back to
    ruptures-based Hartigan's dip test approximation.
  - DuckDB is a compiled extension loaded at runtime — bundled via collect_dynamic_libs.
  - cryptography uses OpenSSL via cffi — bundled with its .so/.dll.
  - The UI dist/ directory is bundled so the API can serve the SPA.
"""
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_dynamic_libs, collect_data_files

block_cipher = None

# ── Data files to bundle ──────────────────────────────────────────────────────
datas = [
    # Config files
    ("config/*.yaml",   "config"),
    # UI production build
    ("ui/dist",         "ui/dist"),
    # Security docs (for --help reference)
    ("docs/security.md", "docs"),
]

# Collect DuckDB dynamic libraries
datas += collect_data_files("duckdb")

# ── Hidden imports (not auto-detected by PyInstaller) ────────────────────────
hiddenimports = [
    # DuckDB
    "duckdb",
    # Cryptography
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.backends.openssl.backend",
    # datasketch (MinHash) — pure Python, but ensure submodules included
    "datasketch",
    "datasketch.minhash",
    "datasketch.lsh",
    # scipy (Bowker test fallback)
    "scipy.stats",
    # ruptures (change-point detection, G3)
    "ruptures",
    # numpy
    "numpy",
    "numpy.random",
    # FastAPI / uvicorn internals
    "fastapi",
    "uvicorn.main",
    "uvicorn.config",
    "uvicorn.loops.auto",
    "uvicorn.lifespan.on",
    "fastapi.staticfiles",
    "fastapi.responses",
    # Pydantic
    "pydantic",
    "pydantic_core",
    # Engine modules
    "engine",
    "engine.cli",
    "engine.ingestion",
    "engine.detectors",
    "engine.layer1",
    "engine.scoring",
    "engine.audit",
    "engine.schema",
    "api",
    "api.routers",
    # datagen (for 'satsa gen' command)
    "datagen",
    "datagen.generator",
    "datagen.null_corpus",
]

# ── diptest: optional compiled extension ─────────────────────────────────────
# diptest is a C extension. Test at build time:
try:
    import diptest
    hiddenimports.append("diptest")
except ImportError:
    print("[satsa.spec] WARNING: diptest not installed. G3 will use ruptures fallback.")
    print("[satsa.spec] To include diptest, run: pip install diptest")

# ── Binary collection ─────────────────────────────────────────────────────────
binaries = collect_dynamic_libs("duckdb")
try:
    binaries += collect_dynamic_libs("cryptography")
except Exception:
    pass

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    ["engine/cli.py"],          # Entry point
    pathex=[str(Path("."))],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest", "IPython", "jupyter"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="satsa",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,               # Do not compress — some AV heuristics flag UPX
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
