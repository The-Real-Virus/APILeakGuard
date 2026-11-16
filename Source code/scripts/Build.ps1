param([string]$Python = '.tools/venv/Scripts/python.exe')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
$root = (Get-Location).Path
$work = "$root/.work/build"
foreach ($folder in @("$work/spec","$root/.work/tmp","$root/.work/evidence","$root/release","$root/dist")) {
    [void][IO.Directory]::CreateDirectory($folder)
}
$env:TMP = "$root/.work/tmp"
$env:TEMP = $env:TMP
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYINSTALLER_CONFIG_DIR = "$root/.tools/pyinstaller"
$env:PYTHONHASHSEED = '0'
$env:SOURCE_DATE_EPOCH = '1767225600'
$env:PYTHONPATH = $root

function Invoke-Python {
    & $Python -B @args
    if ($LASTEXITCODE) { throw "Build step failed with exit code $LASTEXITCODE" }
}

function Invoke-Freeze {
    param([string]$Name, [string]$BuildId, [string]$Entry, [string[]]$Options)
    $arguments = @('-m','PyInstaller','--noconfirm','--clean','--noupx','--log-level','WARN',
        '--distpath',"$root/dist",'--workpath',"$work/$BuildId",'--specpath',"$work/spec",
        '--icon',"$root/assets/apileakguard.ico",'--version-file',"$root/assets/windows-version.txt",
        '--paths',$root,'--name',$Name)
    Invoke-Python @arguments @Options "$root/$Entry"
}

foreach ($folder in @('dist/gui','dist/cli','dist/APILeakGuard-v1.0','dist/APILeakGuard','dist/apileakguard-cli')) {
    $fullPath = [IO.Path]::GetFullPath((Join-Path $root $folder))
    if (-not $fullPath.StartsWith("$root\dist\",[StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid build output path' }
    if (Test-Path -LiteralPath $fullPath) {
        $item = Get-Item -LiteralPath $fullPath
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Build output is a reparse point' }
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}
Invoke-Python scripts/make_icon.py
$runtimeData = @()
$basePython = & $Python -B -c "import sys; print(sys.base_prefix)"
if ($LASTEXITCODE) { throw 'Could not identify the base Python runtime.' }
$trustDenylist = Join-Path $basePython 'Lib/codex-rejected-cas.pem'
if (Test-Path -LiteralPath $trustDenylist) {
    $runtimeData = @('--add-data',"$trustDenylist;.")
}
$guiOptions = @('--windowed','--hidden-import','PySide6.QtSvg','--add-data',"$root/assets;assets",
                '--add-data',"$root/fixtures;fixtures") + $runtimeData
Invoke-Freeze -Name 'APILeakGuard' -BuildId 'gui' -Entry 'scripts/gui_entry.py' -Options $guiOptions
Move-Item -LiteralPath "$root/dist/APILeakGuard" -Destination "$root/dist/gui"
Invoke-Freeze -Name 'apileakguard-cli' -BuildId 'cli' -Entry 'scripts/cli_entry.py' -Options $runtimeData
Move-Item -LiteralPath "$root/dist/apileakguard-cli" -Destination "$root/dist/cli"
Invoke-Python scripts/package.py prepare
Invoke-Python scripts/package.py finalize
