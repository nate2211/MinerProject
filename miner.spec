# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

hidden_imports = [
    'blocknet_mining_backend',
    'blocks_blocknet',
    'blocks_miner',
    'blocknet_client',
    'block',
    'registry',
    'monero_job',
    'miner_core',
    'randomx_ctypes',
    'stratum_client',
    'virtualasic',
    'parallel_monero_worker',
    'python_runtime.py',
    'python_usage.py'
    'python_jit.py',
    'p2pool_share_hunter.py',
]

a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[
        ('randomx-dll.dll', '.'),
        ('VirtualASIC.dll', '.'),
        ('ParallelPython.dll', '.'),
        ('PythonRuntime.dll', '.'),
        ('PythonUsage.dll', '.'),
        ('PythonJIT.dll', '.'),
        ('RemoteConnection.dll', '.'),
    ],
    datas=[
        ('virtualasic_monero_scan.cl', '.'),
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NatesMoneroMiner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)