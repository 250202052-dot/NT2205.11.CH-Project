# Chay tu PowerShell. Moi kiem tra chi gui traffic den IP cua lab.
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $startTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1

    # Sensor phai doc ban sao trong network namespace rieng.
    $routerNamespace = docker compose exec -T router readlink /proc/self/ns/net
    $sensorNamespace = docker compose exec -T zeek readlink /proc/self/ns/net
    if ($LASTEXITCODE -ne 0 -or $routerNamespace -eq $sensorNamespace) {
        throw 'Router and Zeek must use separate network namespaces'
    }
    foreach ($direction in @('ingress', 'egress')) {
        $filters = docker compose exec -T router tc filter show dev eth0 $direction
        if ($LASTEXITCODE -ne 0 -or (@($filters | Select-String 'Mirror to device mirror0')).Count -ne 1) {
            throw "Expected exactly one mirror action for $direction"
        }
    }

    Write-Host '1/4: TLS modern va TLS weak'
    $modern = docker compose exec -T client curl -fsSk --max-time 10 --tls-max 1.2 https://172.30.20.10/
    if ($LASTEXITCODE -ne 0 -or ($modern | ConvertFrom-Json).profile -ne 'modern') {
        throw 'TLS modern failed'
    }
    $weak = docker compose exec -T client curl -fsSk --max-time 10 --tls-max 1.2 --ciphers 'AES128-SHA:@SECLEVEL=0' https://172.30.20.11/
    if ($LASTEXITCODE -ne 0 -or ($weak | ConvertFrom-Json).profile -ne 'weak') {
        throw 'TLS weak failed'
    }

    Write-Host '2/4: SSH handshakes (khong gui mat khau)'
    $sshOptions = '-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    $legacyOptions = '-o KexAlgorithms=diffie-hellman-group14-sha1 -o Ciphers=aes128-cbc -o MACs=hmac-sha1 -o HostKeyAlgorithms=ssh-rsa'
    foreach ($target in @('172.30.20.20', '172.30.20.21')) {
        $extra = if ($target -eq '172.30.20.21') { $legacyOptions } else { '' }
        # Chuyen stderr trong container de PowerShell nhan duoc thong bao SSH.
        $result = docker compose exec -T client sh -c "ssh $sshOptions $extra labuser@$target true 2>&1 || true"
        if (($result -join "`n") -notmatch 'Permission denied') {
            throw "SSH handshake did not reach authentication for ${target}: $result"
        }
    }

    # Dem ban sao truoc restart (restart reset interface counters cua sensor).
    $sensorLinks = docker compose exec -T zeek ip -j -s link show mirror0 | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $sensorLinks[0].stats64.rx.packets -le 0) {
        throw 'Zeek mirror interface did not receive packets'
    }

    Write-Host '3/4: Flush log bang cach restart Zeek'
    docker compose restart zeek
    if ($LASTEXITCODE -ne 0) { throw 'Cannot restart Zeek' }

    Write-Host '4/4: Kiem tra JSON metadata cua lan test nay'
    $expectations = @{
        conn = @('172.30.20.10', '172.30.20.11', '172.30.20.20', '172.30.20.21')
        ssl = @('172.30.20.10', '172.30.20.11')
        ssh = @('172.30.20.20', '172.30.20.21')
    }
    foreach ($kind in $expectations.Keys) {
        $records = @(Get-ChildItem -Path "logs/$kind*.log" | Get-Content |
            Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.ts -ge $startTime })
        foreach ($target in $expectations[$kind]) {
            if (-not ($records | Where-Object { $_.'id.resp_h' -eq $target })) {
                throw "Missing new $kind record for $target"
            }
        }
    }
    $certificates = @(Get-ChildItem -Path 'logs/x509*.log' | Get-Content |
        Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.ts -ge $startTime })
    if ($certificates.Count -lt 2) { throw 'Missing TLS certificate metadata' }

    Write-Host 'PASS: mirror hai chieu, namespace sensor rieng, ca 4 endpoints co JSON metadata.' -ForegroundColor Green
}
finally {
    Pop-Location
}
