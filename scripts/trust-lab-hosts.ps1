# Provision known_hosts from the trusted Docker control plane, not network TOFU.
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $entries = @()
    $targets = @(
        @{ Service = 'bastion'; HostName = '[172.30.20.20]:2222'; KeyPath = '/config/ssh_host_keys/ssh_host_ed25519_key.pub' },
        @{ Service = 'web-frontend'; HostName = '172.30.30.10'; KeyPath = '/etc/ssh/hostkeys/ssh_host_ed25519_key.pub' },
        @{ Service = 'backend'; HostName = '172.30.30.20'; KeyPath = '/etc/ssh/hostkeys/ssh_host_ed25519_key.pub' },
        @{ Service = 'db'; HostName = '172.30.30.30'; KeyPath = '/etc/ssh/hostkeys/ssh_host_ed25519_key.pub' }
    )
    foreach ($target in $targets) {
        $key = docker compose exec -T $target.Service cat $target.KeyPath
        if ($LASTEXITCODE -ne 0) { throw "Cannot read host public key: $($target.Service)" }
        $parts = ($key -join '').Trim() -split '\s+'
        if ($parts[0] -ne 'ssh-ed25519' -or $parts.Count -lt 2) { throw 'Invalid public host key' }
        $entries += "$($target.HostName) $($parts[0]) $($parts[1])"
    }
    $entries | docker compose exec -T client sh -c 'cat > /root/.ssh/known_hosts && chmod 600 /root/.ssh/known_hosts'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot provision Admin known_hosts' }
    Write-Host 'Temporary client trusts Bastion/Frontend/Backend/DB host keys read through Docker.'
}
finally { Pop-Location }
