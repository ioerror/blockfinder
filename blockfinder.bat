@echo off
::
:: This .bat file invokes python (on PATH) with the full path of
:: the script 'blockfinder'. This requires 'blockfinder' and
:: 'blockfinder.bat' to be in the same directory.
:: Look at "cmd /c for /?" to understand the "~dp0" label.
::
python "%~dp0\blockfinder" %*
