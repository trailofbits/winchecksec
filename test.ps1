# Powershell is a stupid language, and I hope this is the most I ever write of it.

$winchecksecPath = Join-Path -Path (Get-ChildItem Env:CONFIGURATION).Value -ChildPath "winchecksec.exe"

Write-Host $winchecksecPath

& $winchecksecPath -j $winchecksecPath | Tee-Object -Variable winchecksecOutput

Write-Host $winchecksecOutput

$winchecksecObj = ConvertFrom-Json -InputObject $winchecksecOutput

$boolKeys = @(
    "dynamicBase",
    "aslr",
    "highEntropyVA",
    "forceIntegrity",
    "isolation",
    "nx",
    "seh",
    "cfg",
    "rfg",
    "safeSEH",
    "gs",
    "authenticode",
    "dotNET")

foreach ($boolKey in $boolKeys) {
    $actual = $winchecksecObj.$boolKey.GetType()
    if (-not $actual -Eq [bool]) {
        Write-Host "Fail: expected $boolKey to be a bool, but got $actual instead"
        exit 1
    }
}

$actual = $winchecksecObj.path.GetType()
if (-not $actual -Eq [String]) {
    Write-Host "Fail: expected path to be a String, but got $actual instead"
    exit 1
}

Write-Host "OK"
exit 0
