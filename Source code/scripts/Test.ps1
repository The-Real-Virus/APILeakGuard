param([string]$Python = '.tools/venv/Scripts/python.exe')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$root = (Get-Location).Path
[void][IO.Directory]::CreateDirectory("$root/.work/tmp")
[void][IO.Directory]::CreateDirectory("$root/.work/evidence")
$env:TMP = "$root/.work/tmp"
$env:TEMP = $env:TMP
$env:PYTHONDONTWRITEBYTECODE = '1'
& $Python -B -m unittest discover -s tests -v 2>&1 | Tee-Object -FilePath .work/evidence/contracts-and-core.txt
exit $LASTEXITCODE
