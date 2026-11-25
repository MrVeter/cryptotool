#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$installDir = Join-Path $env:ProgramFiles 'Cryptotool'
$files = @('cryptotool.exe', 'elgamal.dll', 'table.dll', 'vernam.dll', 'libcrypto-3-x64.dll')

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Удаление требует прав администратора: запустите PowerShell от имени администратора.'
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$entries = @($machinePath -split ';' | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ine $installDir.TrimEnd('\') })
[Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'Machine')

if (Test-Path $installDir) {
    foreach ($file in $files) {
        Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $installDir $file)
    }
    if (-not (Get-ChildItem $installDir)) {
        Remove-Item -Force $installDir
    } else {
        Write-Warning "В $installDir остались посторонние файлы, каталог не удалён."
    }
}

Write-Host 'Multi-Algo Cryptotool удалён.'
