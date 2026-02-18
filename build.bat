@echo off
echo === PDF Decryptor Build ===
echo.

echo Installing dependencies...
pip install pikepdf pyinstaller pillow
if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
)

echo.
echo Generating icon...
python generate_icon.py
if errorlevel 1 (
    echo WARNING: Could not create icon, continuing without it.
)

echo.
echo Building .exe with PyInstaller...
if exist pdfdecryptor.ico (
    python -m PyInstaller --onefile --noconsole --icon=pdfdecryptor.ico pdfdecryptor.py
) else (
    python -m PyInstaller --onefile --noconsole pdfdecryptor.py
)
if errorlevel 1 (
    echo ERROR: PyInstaller failed.
    pause
    exit /b 1
)

echo.
echo Copying files to release/ ...
if not exist release mkdir release
copy /y dist\pdfdecryptor.exe release\

echo.
echo === Build complete ===
echo Output: release\pdfdecryptor.exe
pause
