#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$installDir = Join-Path $env:ProgramFiles 'Cryptotool'
$sourceDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\bin'
$files = @('cryptotool.exe', 'elgamal.dll', 'table.dll', 'vernam.dll', 'libcrypto-3-x64.dll')

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Установка требует прав администратора: запустите PowerShell от имени администратора.'
}

foreach ($file in $files) {
    if (-not (Test-Path (Join-Path $sourceDir $file))) {
        Write-Error "Не найден $sourceDir\$file. Сначала соберите проект (cmake или make)."
    }
}

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
foreach ($file in $files) {
    Copy-Item -Force (Join-Path $sourceDir $file) $installDir
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$entries = @($machinePath -split ';' | Where-Object { $_ -ne '' })
$alreadyPresent = $entries | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') }
if (-not $alreadyPresent) {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $installDir) -join ';'), 'Machine')
}

Write-Host "Установлено в $installDir. Откройте новое окно терминала и выполните: cryptotool --help"
