@echo off
REM RFTOOL-C5 App — APK 构建脚本
REM 前置: Node.js 18+, Android Studio (SDK + NDK)
REM 用法: 双击或在 app 目录运行 build_apk.bat

setlocal
cd /d "%~dp0"

echo [1/4] 安装 npm 依赖...
call npm install
if errorlevel 1 ( echo npm install 失败 & pause & exit /b 1 )

echo [2/4] 添加 Android 平台...
if not exist "android" (
    call npx cap add android
) else (
    echo android 目录已存在, 跳过
)

echo [3/4] 同步 web 资源到 Android...
call npx cap sync android
if errorlevel 1 ( echo cap sync 失败 & pause & exit /b 1 )

echo [4/4] 构建 Debug APK...
cd android
call gradlew.bat assembleDebug
if errorlevel 1 ( echo 构建失败 & pause & exit /b 1 )

echo.
echo ========================================
echo  构建成功!
echo  APK 位置: android\app\build\outputs\apk\debug\app-debug.apk
echo ========================================
pause
