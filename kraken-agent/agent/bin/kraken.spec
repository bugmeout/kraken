# -*- mode: python -*-
a = Analysis(['kraken.py'],
             pathex=['C:\\Users\\a367761\\Desktop\\kraken\\kraken-agent\\agent\\bin'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='kraken.exe',
          debug=False,
          strip=None,
          upx=True,
          console=True )
