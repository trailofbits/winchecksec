# Powershell is a stupid language, and I hope this is the most I ever write of it.

$winchecksecPath = Join-Path -Path (Get-ChildItem Env:CONFIGURATION).Value -ChildPath "winchecksec.exe"

$winchecksecOutput = & $winchecksecPath -j $winchecksecPath

Write-Host $winchecksecOutput

$parser = New-Object Web.Script.Serialization.JavaScriptSerializer
$parser.MaxJsonLength = $winchecksecOutput.length
$winchecksecObj = $parser.DeserializeObject($winchecksecOutput)

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
    $actual = $winchecksecObj[$boolKey].GetType()
    if (-not $actual -Eq [bool]) {
        Write-Host "Fail: expected $boolKey to be a bool, but got $actual instead"
        exit 1
    }
}

$actual = $winchecksecObj["path"].GetType()
if (-not $actual -Eq [String]) {
    Write-Host "Fail: expected path to be a String, but got $actual instead"
    exit 1
}

Write-Host "OK"
exit 0
