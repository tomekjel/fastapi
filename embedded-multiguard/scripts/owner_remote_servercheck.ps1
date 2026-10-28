$ErrorActionPreference='Stop'
if ($env:RUNNER_NAME -ne 'ROG') { throw 'Wrong runner' }
if ([string]::IsNullOrWhiteSpace($env:SSH_HOST) -or [string]::IsNullOrWhiteSpace($env:SSH_USER) -or [string]::IsNullOrWhiteSpace($env:SSH_KEY)) { throw 'BLOCKED: missing production SSH secrets' }
$port=22
if ($env:SSH_PORT) { $port=[int]$env:SSH_PORT }
$keyFile=Join-Path $env:RUNNER_TEMP 'owner-v12-ssh-key'
try {
  $keyText=$env:SSH_KEY.Replace([string][char]13+[string][char]10,[string][char]10).TrimEnd()+[string][char]10
  [IO.File]::WriteAllText($keyFile,$keyText,[Text.UTF8Encoding]::new($false))
  & icacls.exe $keyFile /inheritance:r /grant:r ($env:USERNAME+':R') | Out-Null
  $remote='set -eu; test -f /opt/multiservis/app/main.py; test -x /opt/multiservis/.venv/bin/python; systemctl is-active multiservis-api.service; test -d /opt/multiservis/app/routers; echo PASS:CT103-ready'
  & ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=12 -i $keyFile -p $port ($env:SSH_USER+'@'+$env:SSH_HOST) $remote
  if ($LASTEXITCODE -ne 0) { throw 'CT103 preflight failed' }
} finally { Remove-Item -LiteralPath $keyFile -Force -ErrorAction SilentlyContinue }
