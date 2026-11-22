<#
  Keep Hub's Windows setup run for real (administrator, services, %ProgramData%): one scenario
  of .github/workflows/windows.yml. The scenarios share one computer and run in order. Adapted
  from ShareKeep's scripts/ci/windows-install.ps1.

  -Scenario install         Setup /S with no app registered (acceptance test 24): the service
                            runs as its own account; other computers reach only the
                            certificate page (16080), and the admin address (16081) is on
                            127.0.0.1; the data folder belongs to the
                            administrators, the computer's users may read admin.token and
                            nothing in keys\; the firewall rule "Keep Hub" is for the hub
                            program; Installed apps lists it with its version order and silent
                            uninstall.
  -Scenario upgrade         Setup /S again: still running, the same certificate.
  -Scenario older           The setup made as version 0.0.1: refused with exit code 4, nothing
                            changed (acceptance test 26).
  -Scenario apps            Two apps register through the admin address, as their desktop
                            programs do; their ports open.
  -Scenario remove-refused  uninstall.exe /S with the two apps registered: exit code 5, nothing
                            removed, and registered-apps names both (acceptance test 25: the
                            interactive uninstaller names them and asks again).
  -Scenario remove          uninstall.exe /S /FORCE: the service, the rule, the program and
                            the registration go; the data folder stays.
  -Scenario reinstall       Setup /S after removing: the same certificate, both apps still
                            registered (acceptance test 25).
  -Scenario clean           uninstall.exe /S /FORCE /DELETEDATA: the data folder goes too.

  This is a CI script: PowerShell runs here, never in Keep Hub or its setup. Needs
  `cargo xtask installer`, and for -Scenario older the same with KEEP_HUB_VERSION=0.0.1
  (dist\). Each scenario's notes go to $Artifacts\<scenario>.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install', 'upgrade', 'older', 'apps', 'remove-refused', 'remove', 'reinstall', 'clean')]
    [string]$Scenario,
    [string]$Artifacts = (Join-Path $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }) 'kh-artifacts')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Service = 'KeepHub'
$Account = 'NT SERVICE\KeepHub'
$Data = Join-Path $env:ProgramData 'Keep Hub'
$InstallDir = Join-Path $env:ProgramFiles 'Keep Hub'
$Hub = Join-Path $InstallDir 'keep-hub.exe'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Keep Hub'
$Rule = 'Keep Hub'
$OlderVersion = '0.0.1'
$Fingerprint = Join-Path $Artifacts 'fingerprint.txt'
$Version = Join-Path $Artifacts 'version.txt'
$Out = Join-Path $Artifacts $Scenario
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Fail([string]$why) { throw "FAILED ($Scenario): $why" }
function Note([string]$line) { Write-Output $line; Add-Content -Path (Join-Path $Out 'steps.log') -Value $line }

function Get-Setup([bool]$Older = $false) {
    $all = @(Get-ChildItem -Path (Join-Path $Root 'dist') -Filter 'keep-hub-*-windows-x64-setup.exe')
    $found = @($all | Where-Object { ($_.Name -like "keep-hub-$OlderVersion-*") -eq $Older })
    if ($found.Count -ne 1) { Fail "expected one $(if ($Older) { 'older ' })setup in dist\, found $($found.Count): run cargo xtask installer" }
    return $found[0].FullName
}

function Invoke-Setup([string[]]$Arguments, [int]$Expect = 0, [bool]$Older = $false) {
    $setup = Get-Setup $Older
    Note "> $(Split-Path $setup -Leaf) $($Arguments -join ' ')"
    $p = Start-Process -FilePath $setup -ArgumentList $Arguments -Wait -PassThru
    Note "  exit code $($p.ExitCode)"
    if ($p.ExitCode -ne $Expect) { Fail "Setup exited $($p.ExitCode), expected $Expect" }
}

function Invoke-Uninstall([string[]]$Arguments, [int]$Expect = 0) {
    $uninstaller = Join-Path $InstallDir 'uninstall.exe'
    Note "> uninstall.exe $($Arguments -join ' ')"
    # NSIS runs the uninstaller from a copy and returns at once: _?= runs it in place, so
    # this waits for it (it then can't delete itself: done below)
    $p = Start-Process -FilePath $uninstaller -ArgumentList ($Arguments + @("_?=$InstallDir")) -Wait -PassThru
    Note "  exit code $($p.ExitCode)"
    if ($p.ExitCode -ne $Expect) { Fail "the uninstaller exited $($p.ExitCode), expected $Expect" }
    if ($Expect -eq 0) {
        Remove-Item -Force $uninstaller -ErrorAction SilentlyContinue
        Remove-Item -Force $InstallDir -ErrorAction SilentlyContinue
    }
}

function Get-Hub { Get-CimInstance -ClassName Win32_Service -Filter "Name='$Service'" }

function Assert-HubRunning {
    $s = Get-Hub
    if (-not $s) { Fail "the service $Service isn't installed" }
    if ($s.StartName -ne $Account) { Fail "the service runs as $($s.StartName), not $Account" }
    for ($i = 0; $i -lt 30 -and (Get-Hub).State -ne 'Running'; $i++) { Start-Sleep -Seconds 1 }
    if ((Get-Hub).State -ne 'Running') { Fail "the service is $((Get-Hub).State)" }
    # the admin address answers (with no token: 401)
    for ($i = 0; $i -lt 30; $i++) {
        try { $null = Invoke-WebRequest -Uri 'http://127.0.0.1:16081/admin/v1/status' -UseBasicParsing; break }
        catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { break }
            Start-Sleep -Seconds 1
        }
    }
    Note "  service $Service running as $Account"
}

function Get-HubFingerprint {
    $status = & $Hub status --data $Data
    if ($LASTEXITCODE -ne 0) { Fail "keep-hub status failed" }
    $status | Out-File -FilePath (Join-Path $Out 'status.json')
    $fp = ($status | ConvertFrom-Json).certificate.fingerprint
    if (-not $fp) { Fail "the hub's status has no certificate fingerprint" }
    return $fp
}

function Assert-FirewallRule([bool]$present) {
    $text = & netsh.exe advfirewall firewall show rule name="$Rule" verbose
    $has = ($LASTEXITCODE -eq 0)
    # netsh exits 1 when the rule isn't there; clear it once it has been read
    $global:LASTEXITCODE = 0
    if ($has -ne $present) { Fail "the firewall rule '$Rule' is $(if ($has) { 'there' } else { 'missing' })" }
    if ($present) {
        $text | Out-File -FilePath (Join-Path $Out 'firewall.txt')
        $joined = $text -join "`n"
        if ($joined -notmatch [regex]::Escape($Hub)) { Fail "the firewall rule isn't for $Hub" }
        if ($joined -match 'Public') { Fail "the firewall rule covers public networks" }
    }
    Note "  firewall rule '$Rule' $(if ($present) { 'there, for the hub program' } else { 'gone' })"
}

function Get-Token { (Get-Content -Raw -Path (Join-Path $Data 'admin.token')).Trim() }

# The household's first administrator in these runs (test values, not secrets).
$AdminName = 'Test Administrator'
$AdminPassword = 'ci-test-password-1'
$Pin = '246810'

function Invoke-Admin([string]$Method, [string]$Path, $Body = $null, [string]$Session = '') {
    $headers = @{ Authorization = "Bearer $(Get-Token)" }
    if ($Session) { $headers['Keep-Admin-Session'] = $Session }
    $uri = "http://127.0.0.1:16081/admin/v1/$Path"
    if ($null -ne $Body) {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress)
    }
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
}

# An administrator's session: the first set-up the first time, signing in afterwards.
function Get-Session {
    try {
        $r = Invoke-Admin 'POST' 'setup' @{ name = $AdminName; password = $AdminPassword; pin = $Pin }
        Note "  first set-up: $AdminName is the first administrator"
        return $r.session
    }
    catch {
        if (-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 409) { throw }
    }
    return (Invoke-Admin 'POST' 'session' @{ name = $AdminName; password = $AdminPassword }).session
}

function Get-Listening {
    $hubPid = (Get-Hub).ProcessId
    @(Get-NetTCPConnection -State Listen -OwningProcess $hubPid -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty LocalPort | Sort-Object -Unique)
}

# The ports other computers can reach: the hub's listeners on any address but loopback. (The
# certificate page's front on 16080 passes each request to a small server on 127.0.0.1 at a
# port of its own, as ShareKeep's: that one only this computer reaches.)
function Get-Reachable {
    $hubPid = (Get-Hub).ProcessId
    @(Get-NetTCPConnection -State Listen -OwningProcess $hubPid -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -ne '127.0.0.1' -and $_.LocalAddress -ne '::1' } |
        Select-Object -ExpandProperty LocalPort | Sort-Object -Unique)
}

function Get-LoopbackOnly([int]$port) {
    $hubPid = (Get-Hub).ProcessId
    $on = @(Get-NetTCPConnection -State Listen -OwningProcess $hubPid -LocalPort $port -ErrorAction SilentlyContinue)
    return ($on.Count -gt 0) -and -not ($on | Where-Object { $_.LocalAddress -ne '127.0.0.1' })
}

function Save-Logs {
    $log = Join-Path $Data 'hub.log'
    if (Test-Path $log) { Copy-Item $log (Join-Path $Out 'hub.log') -ErrorAction SilentlyContinue }
}

try {
    switch ($Scenario) {
        'install' {
            Invoke-Setup @('/S')
            foreach ($f in @('keep-hub.exe', 'THIRD-PARTY-LICENSES.txt', 'LICENSE-MIT', 'LICENSE-APACHE', 'NOTICE', 'uninstall.exe')) {
                if (-not (Test-Path (Join-Path $InstallDir $f))) { Fail "$f isn't installed" }
            }
            Assert-HubRunning
            if (-not (Test-Path (Join-Path $Data 'hub.json'))) { Fail "the hub's data folder has no hub.json" }
            # acceptance test 24: the admin address and the certificate page only
            Start-Sleep -Seconds 2
            Note "  listening on $((Get-Listening) -join ', ')"
            $reachable = Get-Reachable
            Note "  reachable from the network: $($reachable -join ', ')"
            if (($reachable -join ',') -ne '16080') { Fail "other computers reach the hub on $($reachable -join ', '), not the certificate page (16080) only" }
            if (-not (Get-LoopbackOnly 16081)) { Fail "the admin address isn't on 127.0.0.1 only" }
            # the data folder: the administrators' own; the users read the admin token only
            $owner = (Get-Acl -Path $Data).Owner
            if ($owner -ne 'BUILTIN\Administrators') { Fail "the data folder belongs to $owner" }
            $tokenAcl = (Get-Acl -Path (Join-Path $Data 'admin.token')).Access | Where-Object { $_.IdentityReference.Value -eq 'BUILTIN\Users' }
            if (-not $tokenAcl) { Fail "the computer's users can't read admin.token" }
            foreach ($secret in @('keys', 'hub.sqlite')) {
                $p = Join-Path $Data $secret
                if (Test-Path $p) {
                    $users = (Get-Acl -Path $p).Access | Where-Object { $_.IdentityReference.Value -eq 'BUILTIN\Users' -or $_.IdentityReference.Value -eq 'Everyone' }
                    if ($users) { Fail "$secret is readable by the computer's users" }
                }
            }
            $svcAcl = (Get-Acl -Path $Data).Access | Where-Object { $_.IdentityReference.Value -eq $Account }
            if (-not $svcAcl) { Fail "the service has no permission on its data folder" }
            Note "  data folder: owner $owner; users read admin.token; keys and the registry are not theirs"
            Assert-FirewallRule $true
            $k = Get-ItemProperty -Path $UninstallKey
            if (-not $k.DisplayVersion -or -not $k.VersionOrder -or -not $k.QuietUninstallString) { Fail "Installed apps lacks the version, its order or the silent uninstall" }
            Note "  Installed apps: Keep Hub $($k.DisplayVersion) ($($k.VersionOrder))"
            $k.DisplayVersion | Out-File -FilePath $Version -NoNewline
            Get-HubFingerprint | Out-File -FilePath $Fingerprint -NoNewline
            Note "  certificate $(Get-Content $Fingerprint)"
        }
        'upgrade' {
            Invoke-Setup @('/S')
            Assert-HubRunning
            $fp = Get-HubFingerprint
            if ($fp -ne (Get-Content $Fingerprint)) { Fail "the certificate changed: $fp" }
            Note "  same certificate: paired phones keep working"
        }
        'older' {
            # acceptance test 26
            Invoke-Setup @('/S') -Expect 4 -Older $true
            $k = Get-ItemProperty -Path $UninstallKey
            if ($k.DisplayVersion -ne (Get-Content $Version)) { Fail "Installed apps now says $($k.DisplayVersion)" }
            Assert-HubRunning
            $fp = Get-HubFingerprint
            if ($fp -ne (Get-Content $Fingerprint)) { Fail "the certificate changed: $fp" }
            Note "  version $OlderVersion refused; Keep Hub $($k.DisplayVersion) still installed and running"
        }
        'apps' {
            # acceptance test 34: a new app needs an administrator's session
            $body = @{ id = 'vacapick'; title = 'VacaPick'; version = '1.0.0'; protocol = 1; public_port = 16443; loopback_port = 26443; money = $false; guests = $false }
            $refused = $false
            try { $null = Invoke-Admin 'POST' 'apps' $body }
            catch {
                $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                # 409: setup_needed before the first set-up; 401: administrator_needed after
                if ($code -ne 401 -and $code -ne 409) { throw }
                $refused = $true
            }
            if (-not $refused) { Fail "a new app was registered without an administrator's session" }
            Note "  a new app without a session: refused"
            $session = Get-Session
            foreach ($a in @(
                    @{ id = 'vacapick'; title = 'VacaPick'; public_port = 16443; loopback_port = 26443 },
                    @{ id = 'carpick'; title = 'CarPick'; public_port = 16444; loopback_port = 26444 })) {
                $body = @{ id = $a.id; title = $a.title; version = '1.0.0'; protocol = 1; public_port = $a.public_port; loopback_port = $a.loopback_port; money = $false; guests = $false }
                $r = Invoke-Admin 'POST' 'apps' $body -Session $session
                if (-not $r.secret) { Fail "registering $($a.id) gave no secret" }
                Note "  $($a.title) registered"
            }
            Start-Sleep -Seconds 1
            $ports = Get-Listening
            Note "  listening on $($ports -join ', ')"
            foreach ($p in @(16443, 16444)) { if ($ports -notcontains $p) { Fail "port $p isn't open" } }
            $apps = (Invoke-Admin 'GET' 'apps').apps
            if (@($apps).Count -ne 2) { Fail "the hub has $(@($apps).Count) apps" }
            # acceptance test 32, on the installed hub while the service runs: an
            # administrator of this computer sets a new password from the command line
            'ci-reset-password-2' | & $Hub reset-administrator --name $AdminName --data $Data | Out-Null
            if ($LASTEXITCODE -ne 0) { Fail "keep-hub reset-administrator failed" }
            $null = Invoke-Admin 'POST' 'session' @{ name = $AdminName; password = 'ci-reset-password-2' }
            $AdminPassword | & $Hub reset-administrator --name $AdminName --data $Data | Out-Null
            if ($LASTEXITCODE -ne 0) { Fail "keep-hub reset-administrator failed the second time" }
            $null = Get-Session
            if (@((Invoke-Admin 'GET' 'apps').apps).Count -ne 2) { Fail "resetting the password changed the apps" }
            Note "  reset-administrator: a new password, the apps unchanged"
        }
        'remove-refused' {
            # acceptance test 25: the uninstaller names the apps and asks again; silently, it
            # refuses (keep-launcher asks the person, then passes /FORCE)
            $named = & $Hub registered-apps --data $Data
            Note "  registered-apps: $named"
            if ($named -notmatch 'VacaPick' -or $named -notmatch 'CarPick') { Fail "registered-apps said '$named'" }
            Invoke-Uninstall @('/S') -Expect 5
            Assert-HubRunning
            if (-not (Test-Path $Hub)) { Fail "the program was removed" }
            if (-not (Test-Path $UninstallKey)) { Fail "Installed apps no longer lists Keep Hub" }
            Assert-FirewallRule $true
            Note "  nothing removed"
        }
        'remove' {
            Invoke-Uninstall @('/S', '/FORCE')
            if (Get-Hub) { Fail "the service is still installed" }
            Assert-FirewallRule $false
            if (Test-Path $Hub) { Fail "the program is still there" }
            if (Test-Path $UninstallKey) { Fail "Installed apps still lists Keep Hub" }
            if (-not (Test-Path (Join-Path $Data 'hub.json'))) { Fail "the data folder was removed" }
            if (-not (Test-Path (Join-Path $Data 'hub.sqlite'))) { Fail "the registry was removed" }
            Note "  the data stays in $Data"
        }
        'reinstall' {
            Invoke-Setup @('/S')
            Assert-HubRunning
            $fp = Get-HubFingerprint
            if ($fp -ne (Get-Content $Fingerprint)) { Fail "the certificate changed after reinstalling: $fp" }
            $apps = @((Invoke-Admin 'GET' 'apps').apps)
            $ids = ($apps | ForEach-Object { $_.id } | Sort-Object) -join ','
            if ($ids -ne 'carpick,vacapick') { Fail "after reinstalling the hub has apps '$ids'" }
            Note "  same certificate and the same apps after removing and installing again"
        }
        'clean' {
            Invoke-Uninstall @('/S', '/FORCE', '/DELETEDATA')
            if (Get-Hub) { Fail "the service is still installed" }
            if (Test-Path $Data) { Fail "the data folder is still there" }
            Note "  no Keep Hub and no data left"
        }
    }
    Note "PASSED ($Scenario)"
}
finally {
    Save-Logs
}
# A scenario that got here passed (a failure throws): don't let a native command's exit code
# from the checks above become the step's result.
exit 0
