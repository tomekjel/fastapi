$ErrorActionPreference='Stop'
if ($env:RUNNER_NAME -cne 'ROG') { throw 'READONLY_GROUP_CHECK_WRONG_RUNNER' }
if ([string]::IsNullOrWhiteSpace($env:SSH_HOST) -or
    [string]::IsNullOrWhiteSpace($env:SSH_USER) -or
    [string]::IsNullOrWhiteSpace($env:SSH_KEY)) {
  throw 'READONLY_GROUP_CHECK_SSH_NOT_CONFIGURED'
}
$port=22
if ($env:SSH_PORT) { $port=[int]$env:SSH_PORT }
$source=Join-Path $PSScriptRoot 'owner_mesh_groups_readonly.py'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'READONLY_GROUP_CHECK_SCRIPT_NOT_FOUND' }
$keyFile=Join-Path $env:RUNNER_TEMP 'owner-mesh-readonly-ssh-key'
try {
  $keyText=$env:SSH_KEY.Replace([string][char]13+[string][char]10,[string][char]10).TrimEnd()+[string][char]10
  [IO.File]::WriteAllText($keyFile,$keyText,[Text.UTF8Encoding]::new($false))
  & icacls.exe $keyFile /inheritance:r /grant:r ($env:USERNAME+':R') | Out-Null
  # Stream the audited Python source over SSH stdin: no deployment, no server file change.
  Get-Content -LiteralPath $source -Raw -Encoding UTF8 |
    & ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=12 -i $keyFile -p $port ($env:SSH_USER+'@'+$env:SSH_HOST) 'python3 -'
  if ($LASTEXITCODE -ne 0) { throw 'READONLY_MESH_PREFLIGHT_BLOCKED' }
} finally {
  Remove-Item -LiteralPath $keyFile -Force -ErrorAction SilentlyContinue
}
