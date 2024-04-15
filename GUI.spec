# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['GUI.py'],
    pathex=[],
    binaries=[],
    datas=[('model_artifacts', 'model_artifacts'), ('packet_info.csv', '.'), ('all_packets_with_predictions.csv', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='GUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
app = BUNDLE(
    exe,
    name='GUI.app',
    icon=None,
    bundle_identifier=None,
)
