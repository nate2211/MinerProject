# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# List your hidden imports to ensure they are packed
hidden_imports = [
    'blocks_blocknet',
    'blocks_miner',
    'blocknet_client',
    'block',
    'registry',
    'monero_job',
    'miner_core',
    'randomx_ctypes',
    'stratum_client'
]

a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[
        # Include the DLL.
        # (Source Path, Dest inside EXE) -> '.' means root of temp folder
        ('randomx-dll.dll', '.'),
    ],
    datas=[],
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

# In One-File mode, we combine everything into the EXE step
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,   # <--- Binaries are now included here
    a.zipfiles,   # <--- Zipfiles are now included here
    a.datas,      # <--- Data files are now included here
    [],
    name='NatesMoneroMiner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True, # Keep True to see mining stats
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)