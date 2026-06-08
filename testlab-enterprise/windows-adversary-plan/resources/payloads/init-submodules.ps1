# Run from repo root: .\testlab-enterprise\windows-adversary-plan\resources\payloads\init-submodules.ps1

$repoRoot = git rev-parse --show-toplevel
Set-Location $repoRoot

git submodule update --init

$payloadBase = "testlab-enterprise/windows-adversary-plan/resources/payloads"

$submodules = @{
    "rce-and-c2"       = @("dnscat2", "react2shell-tool")
    "persistence"      = @("windows-service")
    "user-trigger"     = @("T1189")
    "impact"           = @("ImpactPayload")
    "process-injection"= @("CWLHerpaderping")
    "priv-escalation"  = @("EfsPotato")
    "cred-access"      = @("LsassReflectDumping", "NtdsRawDump")
    "lateral-movement" = @("go-thehash")
}

foreach ($name in $submodules.Keys) {
    $path = "$repoRoot/$payloadBase/$name"
    $folders = $submodules[$name]

    Write-Host "[$name] sparse-checkout: $($folders -join ', ')"
    Set-Location $path
    git sparse-checkout init --cone
    git sparse-checkout set @folders
}

Set-Location $repoRoot
Write-Host "Done."
