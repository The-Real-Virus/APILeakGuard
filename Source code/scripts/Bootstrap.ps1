param([Parameter(Mandatory)][string]$BasePython,[string]$Wheelhouse='')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$root = (Get-Location).Path
[void][IO.Directory]::CreateDirectory("$root/.work/tmp")
[void][IO.Directory]::CreateDirectory("$root/.tools")
$env:TMP = "$root/.work/tmp"
$env:TEMP = $env:TMP
$env:PIP_CACHE_DIR = "$root/.tools/pip-cache"
$env:PIP_CONFIG_FILE = 'NUL'
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
& $BasePython -B -c "import struct,sys; assert sys.version_info[:3] == (3,12,14) and struct.calcsize('P') == 8"
if ($LASTEXITCODE) { throw 'Use Python 3.12.14 x64 for the frozen reference build.' }
& $BasePython -B -m venv .tools/venv
if ($LASTEXITCODE) { throw 'Virtual environment creation failed.' }
$arguments = @('-B','-m','pip','install','--only-binary=:all:','--no-compile','--require-hashes',
               '-r','requirements-win-x64.lock')
if ($Wheelhouse) { $arguments += @('--no-index','--find-links',$Wheelhouse) }
else { $arguments += @('--index-url','https://pypi.org/simple') }
& ./.tools/venv/Scripts/python.exe @arguments
if ($LASTEXITCODE) { throw 'Dependency installation failed.' }
& ./.tools/venv/Scripts/python.exe -B -m pip check
exit $LASTEXITCODE
