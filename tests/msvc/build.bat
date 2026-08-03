@rem Builds the MSVC test programs with a stock Visual Studio 2022 toolchain.
@rem
@rem Every .cpp here is built four ways, because the combinations stress the
@rem emulator differently: /MD imports the C runtime from ucrtbase.dll (so the
@rem emulator can hook it by name), /MT links it statically (so the real runtime
@rem code has to actually execute), and the 32- and 64-bit builds use completely
@rem different calling conventions and floating-point paths.
@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set VS=%ProgramFiles%\Microsoft Visual Studio\2022\Community
if not exist "%VS%\VC\Auxiliary\Build\vcvarsall.bat" (
  echo Visual Studio 2022 not found at "%VS%"
  exit /b 1
)

if not exist bin mkdir bin

for %%A in (x64 x86) do (
  for %%C in (MD MT) do (
    for %%S in (*.cpp) do call :build %%A %%C %%S
  )
)
del /q bin\*.obj 2>nul
echo done
exit /b 0

:build
setlocal
set ARCH=%1
set CRT=%2
set SRC=%3
set NAME=%~n3
if "%ARCH%"=="x64" (set TAG=64) else (set TAG=32)
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" %ARCH% >nul
cl /nologo /EHsc /std:c++17 /O2 /%CRT% /Fo:bin\ /Fe:bin\%NAME%_%CRT%%TAG%.exe %SRC% >bin\build_%NAME%_%CRT%%TAG%.log 2>&1
if errorlevel 1 (
  echo   FAILED %ARCH% /%CRT% %SRC% - see bin\build_%NAME%_%CRT%%TAG%.log
) else (
  echo   bin\%NAME%_%CRT%%TAG%.exe
  del /q bin\build_%NAME%_%CRT%%TAG%.log 2>nul
)
endlocal
exit /b 0
