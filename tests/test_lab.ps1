$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
$originalEnvProfile = $env:TLS_PROFILE
$originalProfile = $null
try {
    function Invoke-LabDocker {
        param([string[]]$DockerArgs)
        $output = & docker @DockerArgs
        if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $($DockerArgs -join ' ')" }
        return $output
    }
    $originalProfile = (Invoke-LabDocker @('compose', 'exec', '-T', 'proxy', 'printenv', 'TLS_PROFILE') -join '').Trim()
    Invoke-LabDocker @('compose', '--profile', 'test', 'up', '-d', '--wait', '--wait-timeout', '60') | Out-Null
    & ./scripts/trust-lab-hosts.ps1
    $startTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1

    Write-Host '1/3: Test modern/weak TLS sequentially on ONE proxy'
    foreach ($profile in @('modern', 'weak')) {
        $env:TLS_PROFILE = $profile
        Invoke-LabDocker @('compose', 'up', '-d', '--no-deps', '--wait', 'proxy') | Out-Null
        if ($profile -eq 'modern') {
            $cert = Invoke-LabDocker @('compose', 'exec', '-T', 'proxy', 'cat', '/etc/nginx/tls/modern/server.crt')
            $cert | docker compose exec -T client sh -c 'cat > /tmp/proxy.crt'
            if ($LASTEXITCODE -ne 0) { throw 'Cannot install public TLS certificate' }
            $response = Invoke-LabDocker @('compose', 'exec', '-T', 'client', 'curl', '-fsS', '--max-time', '10', '--tls-max', '1.2', '--cacert', '/tmp/proxy.crt', '--resolve', 'proxy.topic4.lab:443:172.30.20.10', 'https://proxy.topic4.lab/api/status')
        } else {
            $response = Invoke-LabDocker @('compose', 'exec', '-T', 'client', 'curl', '-fsSk', '--max-time', '10', '--tls-max', '1.2', '--ciphers', 'AES128-SHA:@SECLEVEL=0', 'https://172.30.20.10/api/status')
        }
        if (($response | ConvertFrom-Json).db_result -ne 1) { throw 'Frontend/backend/DB path failed' }
        $frontend = Invoke-LabDocker @('compose', 'exec', '-T', 'client', 'curl', '-fsSk', '--max-time', '10', '--tls-max', '1.2', '--ciphers', 'ALL:@SECLEVEL=0', 'https://172.30.20.10/')
        if (($frontend -join '') -notmatch '<title>Nook') { throw 'Shop frontend is missing' }
    }
    Write-Host '2/3: Authenticated ProxyJump and forbidden paths'
    Invoke-LabDocker @('compose', 'exec', '-T', 'client', 'ssh', 'bastion', 'true') | Out-Null
    foreach ($node in @('web-frontend', 'backend', 'db')) {
        $identity = Invoke-LabDocker @('compose', 'exec', '-T', 'client', 'ssh', $node, 'id', '-un')
        if (($identity -join '').Trim() -ne 'labadmin') { throw "ProxyJump failed: $node" }
        $filters = Invoke-LabDocker @('compose', 'exec', '-T', $node, 'tc', 'filter', 'show', 'dev', 'eth0', 'egress')
        if (@($filters | Select-String 'Mirror to device mirror0').Count -ne 1) { throw "Duplicate/missing mirror: $node" }
    }
    function Assert-Blocked {
        param([string]$Source, [string]$Target, [int]$Port)
        & docker compose exec -T $Source nc -z -w 2 $Target $Port
        if ($LASTEXITCODE -eq 0) { throw "Forbidden connection: $Source -> ${Target}:$Port" }
        Invoke-LabDocker @('compose', 'exec', '-T', $Source, 'true') | Out-Null
    }
    foreach ($target in @('172.30.30.10', '172.30.30.20', '172.30.30.30')) { Assert-Blocked client $target 22 }
    Assert-Blocked client 172.30.30.10 8080
    Assert-Blocked client 172.30.30.20 8000
    Assert-Blocked client 172.30.30.30 5432
    Assert-Blocked web-frontend 172.30.30.30 5432
    Assert-Blocked backend 172.30.30.10 8080
    Assert-Blocked web-frontend 172.30.99.32 8000
    $forward = Invoke-LabDocker @('compose', 'exec', '-T', 'client', 'sh', '-c', 'ssh -W 172.30.30.10:8080 bastion 2>&1 && exit 7; exit 0')
    if (($forward -join '') -notmatch 'administratively prohibited') { throw 'PermitOpen failed' }

    Write-Host '3/3: One Zeek receives TLS/SSH and Frontend->Backend->DB metadata'
    Invoke-LabDocker @('compose', 'restart', 'zeek') | Out-Null
    Invoke-LabDocker @('compose', 'up', '-d', '--wait', 'zeek') | Out-Null
    $ssl = @(Get-ChildItem data/lab_metadata/zeek/ssl*.log | Get-Content | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.ts -ge $startTime -and $_.established })
    if (-not ($ssl | Where-Object { $_.cipher -eq 'TLS_RSA_WITH_AES_128_CBC_SHA' })) { throw 'Missing weak TLS metadata' }
    if (-not ($ssl | Where-Object { $_.cipher -match 'ECDHE' })) { throw 'Missing modern TLS metadata' }
    $ssh = @(Get-ChildItem data/lab_metadata/zeek/ssh*.log | Get-Content | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.ts -ge $startTime })
    foreach ($target in @('172.30.20.20', '172.30.30.10', '172.30.30.20', '172.30.30.30')) {
        if (-not ($ssh | Where-Object { $_.'id.resp_h' -eq $target })) { throw "Missing SSH metadata: $target" }
    }
    $connections = @(Get-ChildItem data/lab_metadata/zeek/conn*.log | Get-Content | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.ts -ge $startTime })
    foreach ($flow in @(
        @{ Source = '172.30.30.10'; Target = '172.30.30.20'; Port = 8000 },
        @{ Source = '172.30.30.20'; Target = '172.30.30.30'; Port = 5432 }
    )) {
        if (-not ($connections | Where-Object { $_.'id.orig_h' -eq $flow.Source -and $_.'id.resp_h' -eq $flow.Target -and $_.'id.resp_p' -eq $flow.Port -and $_.orig_bytes -gt 0 -and $_.resp_bytes -gt 0 })) {
            throw "Missing bidirectional internal flow: $($flow.Source) -> $($flow.Target)"
        }
    }
    Write-Host 'PASS: separate Frontend/Backend/DB, one Proxy, Bastion, Router and Zeek.' -ForegroundColor Green
}
finally {
    if ($originalProfile) {
        $env:TLS_PROFILE = $originalProfile
        docker compose up -d --no-deps --wait proxy | Out-Null
    }
    $env:TLS_PROFILE = $originalEnvProfile
    docker compose rm -s -f client | Out-Null
    Pop-Location
}
