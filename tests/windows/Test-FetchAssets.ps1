<#
.SYNOPSIS
Windows test for scripts/fetch-assets.ps1 (task 4G.2): stage a tiny test manifest onto a real
exFAT or NTFS volume labelled ASSETS inside a VHDX, then check the staged files and hashes.

.DESCRIPTION
What it does, in order:
  1. Makes three small test files (random bytes and text; no media) and a test manifest
     (schema 1, the same shape scripts/gen-manifest.py writes) with a "ci" profile (two pinned
     files and one unpinned file) and a "bad" profile (one file whose pinned hash is wrong).
  2. Makes a throw-away TLS certificate for 127.0.0.1 and serves the files over HTTPS on
     loopback with tests/windows/serve_https.py (the fetcher refuses plain http).
     On Windows the certificate is trusted in LocalMachine\Root for the run and removed after;
     elsewhere the fetcher gets it through SSL_CERT_FILE.
  3. On Windows: creates a 256 MiB VHDX with diskpart, makes one GPT partition, formats it
     exFAT (or NTFS) with the label ASSETS and gives it a free drive letter. With -AssetsDir it
     uses that empty folder instead (for running the same checks on Linux with pwsh).
  4. Runs the fetcher under the chosen engine (Windows PowerShell 5.1 "powershell" or
     PowerShell 7 "pwsh") and checks: exit 0, every pinned file under files\<target> with the
     right SHA-256, the unpinned file refused and listed as skipped, profile.json (schema 1,
     profile, fetcher, files and hashes), manifest.json copied byte for byte.
  5. Runs it again without -TargetVolume (Windows: the volume is found by its ASSETS label):
     exit 0 and no new download.
  6. Runs the "bad" profile: exit 1 and the bad file is not on ASSETS.
  7. Points it at a folder that is not ASSETS: exit 2.
  Then detaches the VHDX, stops the server, and removes the certificate.

The harness itself needs PowerShell 7 (it uses the .NET certificate PEM export); the fetcher
under test runs on 5.1 or 7. It writes nothing outside its work folder except the temporary
certificate trust and the VHDX drive letter, both removed at the end.

.PARAMETER Engine
powershell (Windows PowerShell 5.1) or pwsh (PowerShell 7). Default: pwsh.

.PARAMETER FileSystem
exFAT (default, what the AIRLOCK image uses) or NTFS.

.PARAMETER AssetsDir
Use this empty folder as ASSETS instead of a VHDX (no admin rights needed; any OS).

.PARAMETER Python
Python 3 interpreter for the test server. Default: python on Windows, python3 elsewhere.

.PARAMETER KeepWork
Keep the work folder (logs, VHDX) for debugging.

.EXAMPLE
pwsh -NoProfile -File tests\windows\Test-FetchAssets.ps1 -Engine powershell

.NOTES
Exit status: 0 all checks passed, 1 a check failed (one line says which), 2 bad usage.
Run in CI by .github/workflows/windows.yml.
#>
[CmdletBinding()]
param(
    [ValidateSet('powershell', 'pwsh')]
    [string]$Engine = 'pwsh',
    [ValidateSet('exFAT', 'NTFS')]
    [string]$FileSystem = 'exFAT',
    [string]$AssetsDir = '',
    [string]$Python = '',
    [switch]$KeepWork
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path -LiteralPath ([System.IO.Path]::Combine($PSScriptRoot, '..', '..'))).ProviderPath
$Fetcher = [System.IO.Path]::Combine($RepoRoot, 'scripts', 'fetch-assets.ps1')
$Server = Join-Path $PSScriptRoot 'serve_https.py'
$OnWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$script:Failures = 0
$script:CertThumbprint = ''
$script:ServerProcess = $null
$script:VhdPath = ''

function Write-Line([string]$Message) { [Console]::Out.WriteLine("test-fetch-assets: $Message") }

function Write-Failure([string]$Message) {
    [Console]::Error.WriteLine("test-fetch-assets: FAIL: $Message")
    throw [System.InvalidOperationException]::new($Message)
}

function Assert-True([bool]$Condition, [string]$What) {
    if (-not $Condition) { Write-Failure $What }
    Write-Line "ok: $What"
}

function Get-Sha256Hex([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TextSha256Hex([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Build-TestContent([string]$Root) {
    $ci = Join-Path $Root 'ci'
    [void](New-Item -ItemType Directory -Path $ci -Force)
    $bytes = New-Object byte[] 300000
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [System.IO.File]::WriteAllBytes((Join-Path $ci 'sample.bin'), $bytes)
    [System.IO.File]::WriteAllText((Join-Path $ci 'rules.yar'),
        "rule airlock_ci_test { strings: `$a = `"airlock-ci`" condition: `$a }`n")
    [System.IO.File]::WriteAllText((Join-Path $ci 'wrong.bin'), "this is not what the pin says`n")
}

function Build-Manifest([string]$Root, [string]$Base, [string]$OutPath) {
    function Format-Entry([string]$Id, [string]$File, [object]$Sha, [string]$Target, [string[]]$Profiles, [object]$Size) {
        $e = [ordered]@{}
        $e['id'] = $Id
        $e['license'] = 'CC0-1.0'
        $e['profiles'] = $Profiles
        $e['sha256'] = $Sha
        $e['size'] = $Size
        $e['target'] = $Target
        $e['url'] = "$Base/$File"
        $e['verify'] = 'sha256'
        $e['version'] = '1'
        return $e
    }
    $sample = [System.IO.Path]::Combine($Root, 'ci', 'sample.bin')
    $rules = [System.IO.Path]::Combine($Root, 'ci', 'rules.yar')
    $files = @(
        (Format-Entry 'ci_rules' 'ci/rules.yar' (Get-Sha256Hex $rules) 'yara/ci-rules.yar' @('ci') (Get-Item -LiteralPath $rules).Length),
        (Format-Entry 'ci_sample' 'ci/sample.bin' (Get-Sha256Hex $sample) 'ci/sample.bin' @('ci') (Get-Item -LiteralPath $sample).Length),
        (Format-Entry 'ci_unpinned' 'ci/none.bin' $null 'ci/none.bin' @('ci') $null),
        (Format-Entry 'ci_wrong' 'ci/wrong.bin' (Get-TextSha256Hex 'something else') 'ci/wrong.bin' @('bad') $null)
    )
    $feat = [ordered]@{}
    $feat['ai_tiers'] = @()
    $bad = [ordered]@{}
    $bad['description'] = 'test: a file whose pinned hash is wrong'
    $bad['features'] = $feat
    $bad['files'] = @('ci_wrong')
    $ci = [ordered]@{}
    $ci['description'] = 'test: two small pinned files and one unpinned file'
    $ci['features'] = $feat
    $ci['files'] = @('ci_rules', 'ci_sample', 'ci_unpinned')
    $profiles = [ordered]@{}
    $profiles['bad'] = $bad
    $profiles['ci'] = $ci
    $m = [ordered]@{}
    $m['files'] = $files
    $m['profiles'] = $profiles
    $m['release'] = 'v0.0.0-windows-test'
    $m['schema'] = 1
    $json = ConvertTo-Json -InputObject $m -Depth 10
    [System.IO.File]::WriteAllText($OutPath, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

function Install-TestCertificate([string]$WorkDir) {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw [System.ArgumentException]::new('the harness needs PowerShell 7 (pwsh) to make its test certificate.')
    }
    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=127.0.0.1', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddIpAddress([System.Net.IPAddress]::Loopback)
    $san.AddDnsName('localhost')
    $req.CertificateExtensions.Add($san.Build())
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $eku = [System.Security.Cryptography.OidCollection]::new()
    [void]$eku.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false))
    $now = [DateTimeOffset]::UtcNow
    $cert = $req.CreateSelfSigned($now.AddMinutes(-5), $now.AddDays(1))
    $certPem = Join-Path $WorkDir 'tls.crt'
    $keyPem = Join-Path $WorkDir 'tls.key'
    [System.IO.File]::WriteAllText($certPem, $cert.ExportCertificatePem() + "`n")
    [System.IO.File]::WriteAllText($keyPem, $key.ExportPkcs8PrivateKeyPem() + "`n")
    if ($OnWindows) {
        $public = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
        $store.Open('ReadWrite')
        try { $store.Add($public) } finally { $store.Close() }
        $script:CertThumbprint = $public.Thumbprint
        Write-Line "trusted the test certificate $($public.Thumbprint) for this run"
    }
    return @{ Cert = $certPem; Key = $keyPem }
}

function Uninstall-TestCertificate {
    if (-not $script:CertThumbprint) { return }
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    $store.Open('ReadWrite')
    try {
        foreach ($c in @($store.Certificates.Find('FindByThumbprint', $script:CertThumbprint, $false))) { $store.Remove($c) }
    } finally { $store.Close() }
    Write-Line 'removed the test certificate'
    $script:CertThumbprint = ''
}

function Open-TestServer([string]$Root, [hashtable]$Tls, [string]$WorkDir) {
    $py = $Python
    if (-not $py) { if ($OnWindows) { $py = 'python' } else { $py = 'python3' } }
    $portFile = Join-Path $WorkDir 'port'
    $log = Join-Path $WorkDir 'requests.jsonl'
    $argv = @($Server, $Root, $Tls.Cert, $Tls.Key, $portFile, $log) | ForEach-Object { '"' + $_ + '"' }
    $script:ServerProcess = Start-Process -FilePath $py -ArgumentList $argv -PassThru -NoNewWindow `
        -RedirectStandardError (Join-Path $WorkDir 'server.err')
    for ($i = 0; $i -lt 100 -and -not (Test-Path -LiteralPath $portFile); $i++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path -LiteralPath $portFile)) {
        Write-Failure "the test HTTPS server did not start (see $(Join-Path $WorkDir 'server.err'))"
    }
    return @{ Base = "https://127.0.0.1:$((Get-Content -LiteralPath $portFile -Raw).Trim())"; Log = $log }
}

function Close-TestServer {
    if ($null -ne $script:ServerProcess -and -not $script:ServerProcess.HasExited) {
        $script:ServerProcess.Kill()
        $script:ServerProcess.WaitForExit(5000) | Out-Null
    }
}

function Get-FreeDriveLetter {
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    foreach ($l in @('R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Q', 'P', 'O', 'N', 'M')) {
        if ($used -notcontains $l) { return $l }
    }
    Write-Failure 'no free drive letter for the test volume'
}

function Invoke-DiskPart([string[]]$Commands, [string]$WorkDir) {
    $file = Join-Path $WorkDir ('diskpart-' + [guid]::NewGuid().ToString('N') + '.txt')
    [System.IO.File]::WriteAllLines($file, $Commands)
    $out = & diskpart.exe /s $file 2>&1 | Out-String
    $rc = $LASTEXITCODE
    Write-Line ("diskpart: " + (($Commands -join '; ')))
    if ($rc -ne 0) { Write-Failure "diskpart failed (exit $rc): $out" }
    return $out
}

function Mount-TestVhd([string]$WorkDir) {
    $script:VhdPath = Join-Path $WorkDir 'assets.vhdx'
    $letter = Get-FreeDriveLetter
    $fs = $FileSystem.ToLowerInvariant()
    [void](Invoke-DiskPart @(
            "create vdisk file=`"$($script:VhdPath)`" maximum=256 type=expandable",
            "select vdisk file=`"$($script:VhdPath)`"",
            'attach vdisk',
            'convert gpt',
            'create partition primary',
            "format fs=$fs label=ASSETS quick",
            "assign letter=$letter"
        ) $WorkDir)
    $vol = Get-Volume -DriveLetter $letter
    Assert-True ($vol.FileSystemLabel -eq 'ASSETS') "the VHDX volume $letter`: is labelled ASSETS"
    Assert-True ($vol.FileSystem -eq $FileSystem) "the VHDX volume is $FileSystem (got $($vol.FileSystem))"
    return "$letter`:"
}

function Dismount-TestVhd([string]$WorkDir) {
    if (-not $script:VhdPath) { return }
    try {
        [void](Invoke-DiskPart @("select vdisk file=`"$($script:VhdPath)`"", 'detach vdisk') $WorkDir)
    } catch {
        [Console]::Error.WriteLine("test-fetch-assets: could not detach $($script:VhdPath): $_")
    }
    $script:VhdPath = ''
}

function Invoke-Fetcher([string[]]$FetchArgs, [string]$WorkDir, [string]$CertPem) {
    $exe = $Engine
    $argv = @('-NoProfile', '-NonInteractive')
    if ($OnWindows) { $argv += @('-ExecutionPolicy', 'Bypass') }
    $argv += @('-File', $Fetcher) + $FetchArgs
    $saved = @{}
    foreach ($n in @('SSL_CERT_FILE', 'NO_PROXY', 'no_proxy', 'AIRLOCK_ABUSECH_KEY')) {
        $saved[$n] = [Environment]::GetEnvironmentVariable($n)
    }
    try {
        if (-not $OnWindows) { [Environment]::SetEnvironmentVariable('SSL_CERT_FILE', $CertPem) }
        foreach ($n in @('NO_PROXY', 'no_proxy')) {
            $v = [Environment]::GetEnvironmentVariable($n)
            if ($v) { $v = "127.0.0.1,localhost,$v" } else { $v = '127.0.0.1,localhost' }
            [Environment]::SetEnvironmentVariable($n, $v)
        }
        [Environment]::SetEnvironmentVariable('AIRLOCK_ABUSECH_KEY', $null)
        $ErrorActionPreference = 'Continue'
        $out = & $exe @argv 2>&1 | Out-String
        $rc = $LASTEXITCODE
    } finally {
        foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
    }
    Add-Content -LiteralPath (Join-Path $WorkDir 'fetcher.log') -Value ("=== $exe $($FetchArgs -join ' ') -> $rc`n$out")
    return @{ Rc = $rc; Out = $out }
}

function Measure-GetRequest([string]$Log) {
    if (-not (Test-Path -LiteralPath $Log)) { return 0 }
    return @(Get-Content -LiteralPath $Log | Where-Object { $_ -match '"method": "GET"' }).Count
}

function Invoke-Check([string]$WorkDir) {
    $content = Join-Path $WorkDir 'content'
    Build-TestContent $content
    $tls = Install-TestCertificate $WorkDir
    $srv = Open-TestServer $content $tls $WorkDir
    $manifest = Join-Path $WorkDir 'manifest.json'
    Build-Manifest $content $srv.Base $manifest
    $cache = Join-Path $WorkDir 'cache'

    if ($AssetsDir) {
        [void](New-Item -ItemType Directory -Path $AssetsDir -Force)
        $target = (Resolve-Path -LiteralPath $AssetsDir).ProviderPath
        $root = $target
    } elseif ($OnWindows) {
        $target = Mount-TestVhd $WorkDir
        $root = "$target\"
    } else {
        throw [System.ArgumentException]::new('not on Windows: pass -AssetsDir with an empty folder.')
    }

    # 1. Stage the ci profile.
    $r = Invoke-Fetcher @('-Yes', '-Manifest', $manifest, '-Profile', 'ci', '-TargetVolume', $target, '-Cache', $cache) $WorkDir $tls.Cert
    Assert-True ($r.Rc -eq 0) "$Engine stages the ci profile (exit $($r.Rc)): $($r.Out)"
    foreach ($pair in @(@('ci/sample.bin', 'ci/sample.bin'), @('ci/rules.yar', 'yara/ci-rules.yar'))) {
        $staged = [System.IO.Path]::Combine($root, 'files', $pair[1])
        Assert-True (Test-Path -LiteralPath $staged -PathType Leaf) "staged files/$($pair[1])"
        Assert-True ((Get-Sha256Hex $staged) -eq (Get-Sha256Hex (Join-Path $content $pair[0]))) "SHA-256 of files/$($pair[1]) matches the pin"
    }
    Assert-True (-not (Test-Path -LiteralPath ([System.IO.Path]::Combine($root, 'files', 'ci', 'none.bin')))) 'the unpinned file is not staged'
    $prof = Get-Content -LiteralPath (Join-Path $root 'profile.json') -Raw | ConvertFrom-Json
    Assert-True ($prof.schema -eq 1) 'profile.json schema is 1'
    Assert-True ($prof.profile -eq 'ci') 'profile.json names the ci profile'
    Assert-True (([string]$prof.fetcher).StartsWith('fetch-assets.ps1 ')) 'profile.json names fetch-assets.ps1'
    $ids = (@($prof.files | ForEach-Object { $_.id }) | Sort-Object) -join ','
    Assert-True ($ids -eq 'ci_rules,ci_sample') "profile.json lists the staged files (got $ids)"
    foreach ($f in @($prof.files)) {
        $p = [System.IO.Path]::Combine($root, 'files', [string]$f.target)
        Assert-True ((Get-Sha256Hex $p) -eq $f.sha256) "profile.json hash of $($f.id) matches the file on ASSETS"
    }
    $skipped = @($prof.skipped | Where-Object { $_.id -eq 'ci_unpinned' })
    Assert-True ($skipped.Count -eq 1 -and ([string]$skipped[0].reason) -match 'not pinned') 'the unpinned file is listed as skipped (not pinned yet)'
    Assert-True ((Get-Sha256Hex (Join-Path $root 'manifest.json')) -eq (Get-Sha256Hex $manifest)) 'manifest.json copied byte for byte'

    # 2. Run again; on a real volume, let the fetcher find ASSETS by its label.
    $before = Measure-GetRequest $srv.Log
    $again = @('-Yes', '-Manifest', $manifest, '-Profile', 'ci', '-Cache', $cache)
    if ($AssetsDir) { $again += @('-TargetVolume', $target) }
    $r = Invoke-Fetcher $again $WorkDir $tls.Cert
    Assert-True ($r.Rc -eq 0) "rerun exits 0 (exit $($r.Rc)): $($r.Out)"
    Assert-True ((Measure-GetRequest $srv.Log) -eq $before) 'rerun downloads nothing'
    if (-not $AssetsDir) { Assert-True ($r.Out -match 'found the ASSETS volume') 'the ASSETS volume is found by its label' }

    # 3. A file whose hash does not match its pin is refused.
    $r = Invoke-Fetcher @('-Yes', '-Manifest', $manifest, '-Profile', 'bad', '-TargetVolume', $target, '-Cache', $cache) $WorkDir $tls.Cert
    Assert-True ($r.Rc -eq 1) "a wrong hash fails with exit 1 (exit $($r.Rc))"
    Assert-True (-not (Test-Path -LiteralPath ([System.IO.Path]::Combine($root, 'files', 'ci', 'wrong.bin')))) 'the file with the wrong hash is not on ASSETS'

    # 4. A folder that is not ASSETS is refused as a usage error.
    $notAssets = Join-Path $WorkDir 'not-assets'
    [void](New-Item -ItemType Directory -Path $notAssets -Force)
    [System.IO.File]::WriteAllText((Join-Path $notAssets 'keep.txt'), "not an ASSETS partition`n")
    $r = Invoke-Fetcher @('-Yes', '-Manifest', $manifest, '-Profile', 'ci', '-TargetVolume', $notAssets, '-Cache', $cache) $WorkDir $tls.Cert
    Assert-True ($r.Rc -eq 2) "a folder that is not ASSETS is refused with exit 2 (exit $($r.Rc))"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $notAssets 'files'))) 'nothing was written to that folder'
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('airlock-win-test-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $work -Force)
$exitCode = 0
try {
    if (-not (Get-Command $Engine -ErrorAction SilentlyContinue)) {
        throw [System.ArgumentException]::new("$Engine is not installed here. Use -Engine pwsh or -Engine powershell.")
    }
    Write-Line "engine: $Engine; file system: $FileSystem; work folder: $work"
    Invoke-Check $work
    Write-Line 'all checks passed'
} catch [System.ArgumentException] {
    [Console]::Error.WriteLine("test-fetch-assets: $($_.Exception.Message)")
    $exitCode = 2
} catch {
    [Console]::Error.WriteLine("test-fetch-assets: FAIL: $($_.Exception.Message) Fetcher output: $(Join-Path $work 'fetcher.log')")
    $exitCode = 1
} finally {
    Close-TestServer
    Dismount-TestVhd $work
    Uninstall-TestCertificate
    if ($KeepWork -or $exitCode -ne 0) {
        Write-Line "work folder kept: $work"
    } else {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
exit $exitCode
