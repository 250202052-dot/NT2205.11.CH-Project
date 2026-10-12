$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    docker compose config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Invalid Compose configuration' }
    docker compose build client
    if ($LASTEXITCODE -ne 0) { throw 'Cannot build temporary test client' }
    # A temporary container initializes persistent keys, then is removed.
    docker compose run --rm --no-deps --entrypoint sh client /usr/local/bin/init-keys
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize lab public/private keys' }
    docker compose up -d --build --wait --wait-timeout 90
    if ($LASTEXITCODE -ne 0) { throw 'Lab did not become healthy' }
}
finally { Pop-Location }
