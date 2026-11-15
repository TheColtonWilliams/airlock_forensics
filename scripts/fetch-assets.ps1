<#
.SYNOPSIS
Stage tools, hash sets, signatures and models onto the ASSETS partition of a flashed AIRLOCK
drive, on a Windows (or other) computer with internet access. Tasks 2B.11, 4A.4, 4A.7, 4B.15.

.DESCRIPTION
The AIRLOCK drive never goes online. This script downloads every file the chosen profile needs
(listed in manifest.json), checks its SHA-256, copies it onto the drive's ASSETS partition,
checks it again there, and writes profile.json last. It behaves like scripts/fetch-assets.sh.

Files whose manifest entry has no SHA-256 and verify=sha256 are refused (not pinned yet).
Daily-changing files (verify=vendor_signature or trusted_at_staging) have their observed
SHA-256 recorded in profile.json. The abuse.ch key is used for the MalwareBazaar download only
and is never written anywhere.

Runs on Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER ProfileName
Profile from the manifest (default, minimal, full, ...) or a JSON profile file. Alias -Profile.
Asked for when not given (default: "default").

.PARAMETER Manifest
manifest.json from the release (default: manifest.json beside this script, or
..\assets\manifest.json in a repository checkout). manifest.json.sig is copied too.

.PARAMETER TargetVolume
Drive letter of the ASSETS partition (E: or E:\), or a folder. Default: the one volume
labelled ASSETS.

.PARAMETER Cache
Download cache folder, resumable (default %LOCALAPPDATA%\airlock\assets-cache).

.PARAMETER Refresh
Download the daily-changing sets (ClamAV, MalwareBazaar) again; restage changed models.

.PARAMETER AbuseKeyFile
File holding the abuse.ch Auth-Key (first line). Also read from the AIRLOCK_ABUSECH_KEY
environment variable, or asked for (hidden input).

.PARAMETER Yes
Ask nothing. Without a key, MalwareBazaar is skipped.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\fetch-assets.ps1 -Profile default -TargetVolume E:

.NOTES
Exit status: 0 staged, 1 a file failed or the run was refused, 2 usage error.
Test: tests/functional/test_fetch_assets.sh (runs this script under pwsh against a test server).
#>
[CmdletBinding()]
param(
    [Alias('Profile')]
    [string]$ProfileName = '',
    [string]$Manifest = '',
    [Alias('Assets')]
    [string]$TargetVolume = '',
    [string]$Cache = '',
    [switch]$Refresh,
    [string]$AbuseKeyFile = '',
    [switch]$Yes,
    [string]$Examiner = '',
    [string]$Agency = '',
    [string]$CasePrefix = '',
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$FetcherVersion = '0.1.0-dev'
$UserAgent = "airlock-fetch-assets/$FetcherVersion"
$KeyTag = 'malwarebazaar'
$TmpSuffix = '.airlock-tmp'
$Moving = @('vendor_signature', 'trusted_at_staging')
$BoolFeatures = @('autopsy', 'classifiers', 'clamav', 'eztools', 'malwarebazaar', 'nsrl',
    'nvidia_proprietary', 'sift', 'whisper', 'yara')
$TimeoutMs = 60000
$Attempts = 3

class UsageError : System.Exception {
    UsageError([string]$message) : base($message) {}
}
class FetchError : System.Exception {
    FetchError([string]$message) : base($message) {}
}

function Write-Say([string]$Message) { [Console]::Out.WriteLine("fetch-assets: $Message") }
function Write-Warn([string]$Message) { [Console]::Error.WriteLine("fetch-assets: warning: $Message") }

function ConvertTo-IsoText([object]$Value) {
    # PowerShell 7 turns ISO dates read by ConvertFrom-Json into DateTime; write them back as text.
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}

function Get-UtcNow { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Format-Size([object]$Bytes) {
    if ($null -eq $Bytes) { return 'unknown size' }
    $size = [double]$Bytes
    foreach ($unit in @('bytes', 'KB', 'MB', 'GB', 'TB')) {
        if ($size -lt 1000 -or $unit -eq 'TB') {
            if ($unit -eq 'bytes') { return ('{0:N0} bytes' -f $size) }
            return ('{0:N1} {1}' -f $size, $unit)
        }
        $size = $size / 1000
    }
}

function Get-Prop([object]$Object, [string]$Name) {
    # The leading comma keeps a one-element array an array when it leaves the function.
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return , $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return , $p.Value
}

function Get-List([object]$Object, [string]$Name) {
    $v = Get-Prop $Object $Name
    if ($null -eq $v) { return , @() }
    return , @($v)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Test-SafeTarget([string]$Target) {
    if ([string]::IsNullOrEmpty($Target) -or $Target.StartsWith('/') -or $Target.Contains('\') -or
        $Target.Contains(':')) { return $false }
    foreach ($part in $Target.Split('/')) {
        if ($part -eq '' -or $part -eq '.' -or $part -eq '..') { return $false }
    }
    return $true
}

function Join-Target([string]$Root, [string]$Target) {
    if (-not (Test-SafeTarget $Target)) {
        throw [UsageError]::new("unsafe target path '$Target' in the manifest; refusing to stage it.")
    }
    $path = Join-Path $Root 'files'
    foreach ($part in $Target.Split('/')) { $path = Join-Path $path $part }
    return $path
}

function ConvertTo-SortedJson([object]$Value, [int]$Indent = 0) {
    # Sorted keys at every level, two-space indent, like the Python fetcher.
    $pad = ' ' * ($Indent + 2)
    $end = ' ' * $Indent
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [string]) { return (ConvertTo-Json -InputObject $Value -Compress) }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
    }
    $keys = $null
    if ($Value -is [System.Collections.IDictionary]) { $keys = @($Value.Keys | ForEach-Object { [string]$_ }) }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) {
        $keys = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    }
    if ($null -ne $keys) {
        $sorted = [string[]]$keys
        [Array]::Sort($sorted, [StringComparer]::Ordinal)
        if ($sorted.Count -eq 0) { return '{}' }
        $items = foreach ($k in $sorted) {
            $pad + (ConvertTo-Json -InputObject $k -Compress) + ': ' +
            (ConvertTo-SortedJson (Get-Prop $Value $k) ($Indent + 2))
        }
        return "{`n" + ($items -join ",`n") + "`n$end}"
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $arr = @($Value)
        if ($arr.Count -eq 0) { return '[]' }
        $items = foreach ($v in $arr) { $pad + (ConvertTo-SortedJson $v ($Indent + 2)) }
        return "[`n" + ($items -join ",`n") + "`n$end]"
    }
    return (ConvertTo-Json -InputObject ([string]$Value) -Compress)
}

function Write-FileAtomic([string]$Path, [string]$Text) {
    $tmp = $Path + $TmpSuffix
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    $fs = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    Move-Replace $tmp $Path
}

function Move-Replace([string]$Source, [string]$Dest) {
    if (Test-Path -LiteralPath $Dest) {
        try { [System.IO.File]::Replace($Source, $Dest, $null); return } catch {
            Remove-Item -LiteralPath $Dest -Force
        }
    }
    [System.IO.File]::Move($Source, $Dest)
}

function Read-JsonFile([string]$Path) {
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    return (ConvertFrom-Json -InputObject $text)
}

# ------------------------------------------------------------------------------ profile

function Get-ActiveTagSet([string]$Name, [object]$Features) {
    $tags = New-Object System.Collections.Generic.HashSet[string]
    [void]$tags.Add($Name); [void]$tags.Add('all')
    $tiers = Get-Prop $Features 'ai_tiers'
    if ($null -ne $tiers) { foreach ($t in @($tiers)) { [void]$tags.Add("ai_$t") } }
    foreach ($k in $BoolFeatures) { if ((Get-Prop $Features $k) -eq $true) { [void]$tags.Add($k) } }
    return , $tags
}

function Resolve-AssetProfile([object]$ManifestData, [string]$Arg) {
    $profiles = Get-Prop $ManifestData 'profiles'
    $files = @{}
    foreach ($f in @($ManifestData.files)) { $files[[string]$f.id] = $f }
    if (Test-Path -LiteralPath $Arg -PathType Leaf) {
        try { $data = Read-JsonFile $Arg } catch {
            throw [UsageError]::new("$Arg is not valid JSON. On Windows write the profile file as JSON.")
        }
        $name = ''
        $inner = Get-Prop $data 'profiles'
        if ($null -ne $inner) {
            $props = @($inner.PSObject.Properties)
            if ($props.Count -ne 1) { throw [UsageError]::new("$Arg holds several profiles; keep exactly one.") }
            $name = $props[0].Name; $data = $props[0].Value
        }
        $n = Get-Prop $data 'name'
        if ($n) { $name = [string]$n }
        if (-not $name) { $name = [System.IO.Path]::GetFileNameWithoutExtension($Arg) }
        $features = Get-Prop $data 'features'
        if ($null -eq $features) { $features = Get-Prop (Get-Prop $profiles $name) 'features' }
        if ($null -eq $features) { $features = [ordered]@{} }
        $listed = Get-Prop $data 'files'
        if ($null -ne $listed) {
            $ids = @($listed | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        } else {
            $want = Get-ActiveTagSet $name $features
            $ids = @($files.Keys | Where-Object {
                    $f = $files[$_]
                    (Get-Prop $f 'target') -and ((Get-List $f 'profiles') | Where-Object { $want.Contains([string]$_) })
                } | Sort-Object)
        }
    } else {
        $name = $Arg -replace '\.(json|ya?ml)$', ''
        $p = Get-Prop $profiles $name
        if ($null -eq $p) {
            $known = (@($profiles.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object) -join ', '
            throw [UsageError]::new("no profile named '$Arg' in the manifest (known: $known).")
        }
        $features = Get-Prop $p 'features'
        $ids = @((Get-List $p 'files') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Sort-Object)
    }
    $unknown = @($ids | Where-Object { -not $files.ContainsKey($_) })
    if ($unknown.Count -gt 0) {
        throw [UsageError]::new('the profile names files the manifest does not have: ' + ($unknown -join ', '))
    }
    $notAssets = @($ids | Where-Object { -not (Get-Prop $files[$_] 'target') })
    if ($notAssets.Count -gt 0) {
        throw [UsageError]::new('these are not ASSETS files (no target): ' + ($notAssets -join ', '))
    }
    return @{ Name = $name; Features = $features; Ids = $ids; Files = $files }
}

function Test-NeedsKey([object]$Entry) { return ((Get-List $Entry 'profiles') -contains $KeyTag) }

# ------------------------------------------------------------------------------ volume

function Resolve-AssetsRoot([string]$Target) {
    $hasGetVolume = $null -ne (Get-Command Get-Volume -ErrorAction SilentlyContinue)
    if (-not $Target) {
        if (-not $hasGetVolume) {
            throw [UsageError]::new('cannot look up volumes here. Pass -TargetVolume with the ASSETS drive letter or folder.')
        }
        $vols = @(Get-Volume | Where-Object { $_.FileSystemLabel -eq 'ASSETS' })
        if ($vols.Count -eq 0) {
            throw [UsageError]::new('no volume labelled ASSETS found. Plug in the flashed AIRLOCK drive. If ' +
                'Windows gave the ASSETS partition no drive letter, add one in Disk Management (right-click ' +
                'it, Change Drive Letter and Paths) and pass -TargetVolume X:.')
        }
        if ($vols.Count -gt 1) {
            throw [UsageError]::new('more than one volume is labelled ASSETS. Pass -TargetVolume with the right drive letter.')
        }
        if (-not $vols[0].DriveLetter) {
            throw [UsageError]::new('the ASSETS partition has no drive letter. Add one in Disk Management ' +
                '(right-click it, Change Drive Letter and Paths) and pass -TargetVolume X:.')
        }
        Write-Say "found the ASSETS volume: $($vols[0].DriveLetter):"
        return "$($vols[0].DriveLetter):\"
    }
    if ($Target -match '^[A-Za-z]:\\?$') {
        $letter = $Target.Substring(0, 1).ToUpperInvariant()
        if ($hasGetVolume) {
            $vol = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
            if ($null -eq $vol) { throw [UsageError]::new("there is no drive $letter`:. Check the drive letter.") }
            if ($vol.FileSystemLabel -ne 'ASSETS') {
                throw [UsageError]::new("drive $letter`: is labelled '$($vol.FileSystemLabel)', not ASSETS. Give the ASSETS partition of the flashed drive.")
            }
        }
        return "$letter`:\"
    }
    if (Test-Path -LiteralPath $Target -PathType Container) {
        $full = (Resolve-Path -LiteralPath $Target).ProviderPath
        $hasStaging = (Test-Path -LiteralPath (Join-Path $full 'profile.json')) -or
            (Test-Path -LiteralPath (Join-Path $full 'manifest.json'))
        $empty = @(Get-ChildItem -LiteralPath $full -Force).Count -eq 0
        if (-not ($hasStaging -or $empty)) {
            throw [UsageError]::new("$Target is not the ASSETS partition (no profile.json) and is not empty. Give the ASSETS drive letter.")
        }
        return $full
    }
    throw [UsageError]::new("$Target is neither a drive letter nor a folder.")
}

function Get-FreeSpace([string]$Path) {
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    try {
        $di = New-Object System.IO.DriveInfo($full)
        return [long]$di.AvailableFreeSpace
    } catch {
        $drive = Get-PSDrive -Name ($full.Substring(0, 1)) -ErrorAction SilentlyContinue
        if ($null -ne $drive) { return [long]$drive.Free }
        return [long]::MaxValue
    }
}

# ------------------------------------------------------------------------------ HTTP

function Get-HttpResponse([string]$Url, [string]$Method, [string]$Key, [long]$From, [string]$Validator) {
    # Follows up to five https redirects by hand; the key is never sent after a redirect.
    $current = $Url
    $sendKey = $Key
    for ($hop = 0; $hop -lt 6; $hop++) {
        if (-not $current.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
            throw [FetchError]::new("refusing a non-https URL: $current")
        }
        $req = [System.Net.HttpWebRequest]::Create($current)
        $req.Method = $Method
        $req.UserAgent = $UserAgent
        $req.AllowAutoRedirect = $false
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        if ($sendKey) { $req.Headers.Add('Auth-Key', $sendKey) }
        if ($From -gt 0) {
            $req.AddRange([long]$From)
            if ($Validator) { $req.Headers.Add('If-Range', $Validator) }
        }
        $resp = $null
        try { $resp = $req.GetResponse() } catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($null -eq $resp) { throw [FetchError]::new("network error: $($_.Exception.Message)") }
        }
        $code = [int]$resp.StatusCode
        if ($code -ge 300 -and $code -lt 400 -and $resp.Headers['Location']) {
            $next = [Uri]::new([Uri]$current, [string]$resp.Headers['Location']).AbsoluteUri
            $resp.Dispose()
            $current = $next
            $sendKey = ''
            continue
        }
        return $resp
    }
    throw [FetchError]::new('too many redirects')
}

function Get-RemoteSize([string]$Url, [string]$Key) {
    try {
        $headers = @{ 'User-Agent' = $UserAgent }
        if ($Key) { $headers['Auth-Key'] = $Key }
        $r = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -Headers $headers -MaximumRedirection 0 -TimeoutSec 60
        $len = @($r.Headers['Content-Length'])[0]
        if ($len -match '^\d+$') { return [long]$len }
    } catch {
        return $null
    }
    return $null
}

function Invoke-OneDownload([object]$Entry, [string]$Part, [string]$MetaPath, [hashtable]$Meta, [string]$Key, [long]$Have, [string]$Validator) {
    $useKey = ''
    if (Test-NeedsKey $Entry) { $useKey = $Key }
    $resp = Get-HttpResponse ([string]$Entry.url) 'GET' $useKey $Have $Validator
    try {
        $code = [int]$resp.StatusCode
        if ($code -eq 416 -and $Have -gt 0) { return }
        if ($code -ge 400) {
            $msg = "the server answered HTTP $code"
            if (($code -eq 401 -or $code -eq 403) -and $useKey) { $msg += ' (check the abuse.ch key)' }
            throw [FetchError]::new($msg)
        }
        $mode = [System.IO.FileMode]::Create
        if ($Have -gt 0 -and $code -eq 206) {
            $crange = [string]$resp.Headers['Content-Range']
            if (-not $crange.StartsWith("bytes $Have-")) {
                Remove-Item -LiteralPath $Part -Force -ErrorAction SilentlyContinue
                throw [FetchError]::new("the server sent an unexpected range ($crange); rerun.")
            }
            $mode = [System.IO.FileMode]::Append
        } else {
            $Have = 0
        }
        $Meta['etag'] = [string]$resp.Headers['ETag']
        $Meta['last_modified'] = [string]$resp.Headers['Last-Modified']
        Write-FileAtomic $MetaPath (ConvertTo-SortedJson $Meta)
        $total = $null
        if ($resp.ContentLength -ge 0) { $total = $Have + $resp.ContentLength }
        $in = $resp.GetResponseStream()
        $out = [System.IO.File]::Open($Part, $mode, [System.IO.FileAccess]::Write)
        try { $in.CopyTo($out, 1048576); $out.Flush($true) } finally { $out.Dispose(); $in.Dispose() }
        $done = (Get-Item -LiteralPath $Part).Length
        if ($null -ne $total -and $done -lt $total) { throw [FetchError]::new("connection closed after $done of $total bytes") }
    } finally {
        $resp.Dispose()
    }
}

function Get-Download([object]$Entry, [string]$CacheRoot, [string]$Key) {
    $fid = [string]$Entry.id
    $url = [string]$Entry.url
    $expected = Get-Prop $Entry 'sha256'
    $part = Join-Path (Join-Path $CacheRoot 'partial') "$fid.part"
    $metaPath = Join-Path (Join-Path $CacheRoot 'partial') "$fid.part.json"
    $meta = @{}
    if (Test-Path -LiteralPath $metaPath) {
        try {
            $m = Read-JsonFile $metaPath
            foreach ($p in $m.PSObject.Properties) { $meta[$p.Name] = $p.Value }
        } catch { $meta = @{} }
    }
    if ((Get-Prop $meta 'url') -ne $url -or (Get-Prop $meta 'sha256') -ne $expected) {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        $meta = @{ url = $url; sha256 = $expected }
    }
    $ok = $false
    $lastError = 'no data'
    for ($i = 0; $i -lt $Attempts -and -not $ok; $i++) {
        $have = 0
        if (Test-Path -LiteralPath $part) { $have = (Get-Item -LiteralPath $part).Length }
        $validator = ''
        if (-not $expected) {
            $validator = [string](Get-Prop $meta 'etag')
            if (-not $validator) { $validator = [string](Get-Prop $meta 'last_modified') }
            if ($have -gt 0 -and -not $validator) { Remove-Item -LiteralPath $part -Force; $have = 0 }
        }
        try {
            Invoke-OneDownload $Entry $part $metaPath $meta $Key $have $validator
            $ok = $true
        } catch [FetchError] {
            $lastError = $_.Exception.Message
            if ($lastError -match 'HTTP 4\d\d' -and $lastError -notmatch 'HTTP (408|429)') { break }
        } catch {
            $lastError = $_.Exception.Message
        }
    }
    if (-not $ok -or -not (Test-Path -LiteralPath $part)) {
        throw [FetchError]::new("download failed: $lastError. Rerun the same command to resume.")
    }
    $sha = Get-Sha256 $part
    if ($expected -and $sha -ne $expected) {
        Remove-Item -LiteralPath $part, $metaPath -Force -ErrorAction SilentlyContinue
        throw [FetchError]::new("the download does not match its pinned SHA-256 (got $($sha.Substring(0, 16))..., " +
            "want $($expected.Substring(0, 16))...). It was deleted. The file on the server changed or was " +
            'tampered with; do not use it. Report it, or retry later.')
    }
    $blob = Join-Path (Join-Path $CacheRoot 'blobs') $sha
    Move-Replace $part $blob
    Remove-Item -LiteralPath $metaPath -Force -ErrorAction SilentlyContinue
    if (-not $expected) {
        $rec = [ordered]@{ fetched_at = (Get-UtcNow); sha256 = $sha; size = (Get-Item -LiteralPath $blob).Length; url = $url }
        Write-FileAtomic (Join-Path (Join-Path $CacheRoot 'moving') "$fid.json") (ConvertTo-SortedJson $rec)
    }
    return @{ Blob = $blob; Sha = $sha }
}

function Get-CachedMoving([string]$CacheRoot, [string]$Fid, [string]$Url) {
    $recPath = Join-Path (Join-Path $CacheRoot 'moving') "$Fid.json"
    if (-not (Test-Path -LiteralPath $recPath)) { return $null }
    try { $rec = Read-JsonFile $recPath } catch { return $null }
    $sha = [string](Get-Prop $rec 'sha256')
    if ((Get-Prop $rec 'url') -ne $Url -or $sha -notmatch '^[0-9a-f]{64}$') { return $null }
    $blob = Join-Path (Join-Path $CacheRoot 'blobs') $sha
    if (-not (Test-Path -LiteralPath $blob)) { return $null }
    return @{ Blob = $blob; Sha = $sha }
}

function Copy-Verified([string]$Source, [string]$Dest, [string]$Expected) {
    $dir = Split-Path -Parent $Dest
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ((Get-Sha256 $Source) -ne $Expected) {
        Remove-Item -LiteralPath $Source -Force -ErrorAction SilentlyContinue
        throw [FetchError]::new("the cached copy $Source does not match its SHA-256 any more; it was removed. Rerun to download it again.")
    }
    $tmp = $Dest + $TmpSuffix
    $in = [System.IO.File]::OpenRead($Source)
    $out = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try { $in.CopyTo($out, 1048576); $out.Flush($true) } finally { $out.Dispose(); $in.Dispose() }
    if ((Get-Sha256 $tmp) -ne $Expected) {
        Remove-Item -LiteralPath $tmp -Force
        throw [FetchError]::new("the copy on ASSETS ($Dest) did not read back with the right SHA-256. The drive may be failing; try another drive or rerun.")
    }
    Move-Replace $tmp $Dest
}

# ------------------------------------------------------------------------------ main

function Invoke-Fetch {
    $interactive = (-not $Yes) -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $scriptDir = Split-Path -Parent $PSCommandPath
    $manifestPath = $Manifest
    if (-not $manifestPath) {
        $repoAssets = Join-Path (Split-Path -Parent $scriptDir) 'assets'
        foreach ($c in @((Join-Path $scriptDir 'manifest.json'), (Join-Path $repoAssets 'manifest.json'))) {
            if (Test-Path -LiteralPath $c -PathType Leaf) { $manifestPath = $c; break }
        }
    }
    if (-not $manifestPath -or -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw [UsageError]::new('no manifest.json found. Pass -Manifest with the manifest.json from the release.')
    }
    $manifestPath = (Resolve-Path -LiteralPath $manifestPath).ProviderPath
    try { $md = Read-JsonFile $manifestPath } catch {
        throw [UsageError]::new("the manifest $manifestPath is not valid JSON. Download it again.")
    }
    if ((Get-Prop $md 'schema') -ne 1 -or $null -eq (Get-Prop $md 'files')) {
        throw [UsageError]::new("$manifestPath is not an AIRLOCK manifest (schema 1). Download it again.")
    }

    $assets = Resolve-AssetsRoot $TargetVolume

    $choice = $ProfileName
    if (-not $choice) {
        $choice = 'default'
        if ($interactive) {
            [Console]::Out.WriteLine('Profiles:')
            foreach ($p in ($md.profiles.PSObject.Properties | Sort-Object Name)) {
                [Console]::Out.WriteLine(("  {0}: {1}" -f $p.Name, (Get-Prop $p.Value 'description')))
            }
            $answer = Read-Host 'Which profile? [default]'
            if ($answer) { $choice = $answer.Trim() }
        }
    }
    $prof = Resolve-AssetProfile $md $choice
    $entries = @($prof.Ids | ForEach-Object { $prof.Files[$_] })

    $key = [string]$env:AIRLOCK_ABUSECH_KEY
    if (Test-Path Env:\AIRLOCK_ABUSECH_KEY) { Remove-Item Env:\AIRLOCK_ABUSECH_KEY }
    if ($AbuseKeyFile) {
        try { $key = ([string](Get-Content -LiteralPath $AbuseKeyFile -TotalCount 1)).Trim() } catch {
            throw [UsageError]::new("cannot read the key file $AbuseKeyFile.")
        }
    }
    $needsKey = @($entries | Where-Object { Test-NeedsKey $_ }).Count -gt 0
    if (-not $key -and $needsKey -and $interactive) {
        $secure = Read-Host 'abuse.ch Auth-Key for the MalwareBazaar hash list (input hidden; press Enter to skip it)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim() } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    if ($key -and $key -notmatch '^[\x21-\x7e]{8,200}$') {
        throw [UsageError]::new('the abuse.ch key has spaces or odd characters; check it and rerun.')
    }

    $cacheRoot = $Cache
    if (-not $cacheRoot) {
        if ($env:LOCALAPPDATA) { $cacheRoot = Join-Path (Join-Path $env:LOCALAPPDATA 'airlock') 'assets-cache' }
        else { $cacheRoot = Join-Path (Join-Path (Join-Path $HOME '.cache') 'airlock') 'assets' }
    }
    foreach ($sub in @('blobs', 'partial', 'moving')) {
        $d = Join-Path $cacheRoot $sub
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    $cacheRoot = (Resolve-Path -LiteralPath $cacheRoot).ProviderPath

    Write-Say ("profile '{0}': {1} file(s); manifest release {2}" -f $prof.Name, $entries.Count, (Get-Prop $md 'release'))

    # Old profile.json: hashes of daily files already staged, and files to remove.
    $oldFiles = @{}
    $oldPath = Join-Path $assets 'profile.json'
    if (Test-Path -LiteralPath $oldPath) {
        try {
            foreach ($f in @((Read-JsonFile $oldPath).files)) { if ($f) { $oldFiles[[string]$f.id] = $f } }
        } catch { $oldFiles = @{} }
    }

    $items = New-Object System.Collections.ArrayList
    $skipped = [ordered]@{}
    foreach ($e in $entries) {
        $fid = [string]$e.id
        $dest = Join-Target $assets ([string]$e.target)
        $expected = Get-Prop $e 'sha256'
        $isMoving = $Moving -contains [string](Get-Prop $e 'verify')
        $item = @{ Entry = $e; Dest = $dest; Action = ''; Source = ''; Sha = ''; Size = (Get-Prop $e 'size'); StagedAt = '' }
        $prev = $oldFiles[$fid]
        if (-not $expected -and -not $isMoving) {
            $skipped[$fid] = 'not pinned yet: the manifest has no SHA-256 for it, so it cannot be checked'
            continue
        }
        $keyMissing = (Test-NeedsKey $e) -and -not $key
        $tryKeep = $keyMissing -or -not ($isMoving -and $Refresh)
        if ($tryKeep -and (Test-Path -LiteralPath $dest -PathType Leaf)) {
            $want = $expected
            if (-not $want) { $want = [string](Get-Prop $prev 'sha256') }
            $len = (Get-Item -LiteralPath $dest).Length
            $sizeOk = (-not $expected) -or ($null -eq $item.Size) -or ($len -eq $item.Size)
            if ($want -and $sizeOk -and (Get-Sha256 $dest) -eq $want) {
                $item.Action = 'keep'; $item.Sha = $want; $item.Size = $len
                if ((Get-Prop $prev 'sha256') -eq $want -and (Get-Prop $prev 'target') -eq $e.target) {
                    $item.StagedAt = ConvertTo-IsoText (Get-Prop $prev 'staged_at')
                }
                if ($keyMissing) { Write-Warn "$fid`: no abuse.ch key given; keeping the copy staged $($item.StagedAt)" }
                [void]$items.Add($item)
                continue
            }
        }
        if ($keyMissing) { $skipped[$fid] = 'no abuse.ch key given; rerun with a key to stage it'; continue }
        $blob = ''
        if ($expected) { $blob = Join-Path (Join-Path $cacheRoot 'blobs') $expected }
        $hit = $null
        if (-not $expected -and -not $Refresh) { $hit = Get-CachedMoving $cacheRoot $fid ([string]$e.url) }
        if ($expected -and (Test-Path -LiteralPath $blob)) {
            $item.Action = 'copy'; $item.Source = $blob; $item.Sha = $expected; $item.Size = (Get-Item -LiteralPath $blob).Length
        } elseif ($null -ne $hit) {
            $item.Action = 'copy'; $item.Source = $hit.Blob; $item.Sha = $hit.Sha; $item.Size = (Get-Item -LiteralPath $hit.Blob).Length
        } else {
            $item.Action = 'download'
            if ($null -eq $item.Size) {
                $k = ''
                if (Test-NeedsKey $e) { $k = $key }
                $item.Size = Get-RemoteSize ([string]$e.url) $k
            }
        }
        [void]$items.Add($item)
    }
    $keptTargets = @($items | ForEach-Object { [string]$_.Entry.target })
    $prune = New-Object System.Collections.ArrayList
    foreach ($prev in $oldFiles.Values) {
        $t = [string](Get-Prop $prev 'target')
        if (-not $t -or $keptTargets -contains $t -or -not (Test-SafeTarget $t)) { continue }
        $pp = Join-Target $assets $t
        if (Test-Path -LiteralPath $pp -PathType Leaf) { [void]$prune.Add($pp) }
    }
    foreach ($fid in $skipped.Keys) { Write-Warn "skipping $fid`: $($skipped[$fid])" }
    $count = @{ keep = 0; copy = 0; download = 0 }
    foreach ($i in $items) { $count[$i.Action]++ }
    Write-Say ("{0} already on ASSETS and checked, {1} to copy from the cache, {2} to download, {3} old file(s) to remove" -f
        $count.keep, $count.copy, $count.download, $prune.Count)

    # Space check: ASSETS and the cache.
    $need = [long]0; $reclaim = [long]0; $unknown = @()
    foreach ($i in $items) {
        if ($i.Action -eq 'keep') { continue }
        if ($null -eq $i.Size) { $unknown += [string]$i.Entry.id } else { $need += [long]$i.Size }
        if (Test-Path -LiteralPath $i.Dest -PathType Leaf) { $reclaim += (Get-Item -LiteralPath $i.Dest).Length }
    }
    foreach ($pp in $prune) { $reclaim += (Get-Item -LiteralPath $pp).Length }
    $net = [Math]::Max([long]0, $need - $reclaim)
    $free = Get-FreeSpace $assets
    Write-Say ("ASSETS ({0}): {1} free; this profile needs {2} more" -f $assets, (Format-Size $free), (Format-Size $net))
    $dlNeed = [long]0
    foreach ($i in $items) {
        if ($i.Action -ne 'download' -or $null -eq $i.Size) { continue }
        $dlNeed += [long]$i.Size
        $pp = Join-Path (Join-Path $cacheRoot 'partial') "$($i.Entry.id).part"
        if (Test-Path -LiteralPath $pp) { $dlNeed -= (Get-Item -LiteralPath $pp).Length }
    }
    $cacheFree = Get-FreeSpace $cacheRoot
    Write-Say ("download cache ({0}): {1} free; downloads need {2}" -f $cacheRoot, (Format-Size $cacheFree), (Format-Size $dlNeed))
    if ($unknown.Count -gt 0) {
        Write-Warn ("{0} file(s) have no known size ({1}); the space check cannot count them" -f $unknown.Count, ($unknown -join ', '))
    }
    if ($net -gt $free) {
        throw [UsageError]::new(("not enough space on ASSETS: {0} free, {1} needed. Pick a smaller profile (-Profile minimal) or use a larger drive." -f
                (Format-Size $free), (Format-Size $net)))
    }
    if ($dlNeed -gt $cacheFree) {
        throw [UsageError]::new(("not enough space for the download cache: {0} free, {1} needed. Free some space or pass -Cache on a larger disk." -f
                (Format-Size $cacheFree), (Format-Size $dlNeed)))
    }
    if ($DryRun) { Write-Say 'dry run: nothing written'; return 0 }
    if ($interactive) {
        $answer = Read-Host "Stage these files onto $assets? [y/N]"
        if ($answer -notmatch '^(y|yes)$') { Write-Say 'stopped; nothing was written'; return 1 }
    }

    $filesRoot = Join-Path $assets 'files'
    if (Test-Path -LiteralPath $filesRoot) {
        Get-ChildItem -LiteralPath $filesRoot -Recurse -File -Filter "*$TmpSuffix" | Remove-Item -Force
    }
    foreach ($pp in $prune) {
        Remove-Item -LiteralPath $pp -Force
        Write-Say "removed $pp (not in this profile)"
    }

    $now = Get-UtcNow
    $failures = @()
    foreach ($i in $items) {
        $fid = [string]$i.Entry.id
        try {
            if ($i.Action -eq 'download') {
                Write-Say "downloading $fid ($(Format-Size $i.Size))"
                $r = Get-Download $i.Entry $cacheRoot $key
                $i.Source = $r.Blob; $i.Sha = $r.Sha
            }
            if ($i.Action -eq 'copy' -or $i.Action -eq 'download') {
                Copy-Verified $i.Source $i.Dest $i.Sha
                if (-not (Get-Prop $i.Entry 'sha256')) { Write-Say "$fid`: recorded SHA-256 $($i.Sha) ($($i.Entry.verify))" }
                $i.StagedAt = $now
                Write-Say "staged $fid -> files/$($i.Entry.target) (SHA-256 checked twice)"
            }
            if (-not $i.StagedAt) { $i.StagedAt = $now }
        } catch {
            $failures += $fid
            $skipped[$fid] = "failed: $($_.Exception.Message)"
            Write-Warn "$fid`: $($_.Exception.Message)"
        }
    }
    if (Test-Path -LiteralPath $filesRoot) {
        Get-ChildItem -LiteralPath $filesRoot -Recurse -File -Filter "*$TmpSuffix" | Remove-Item -Force
        Get-ChildItem -LiteralPath $filesRoot -Recurse -Directory | Sort-Object { $_.FullName.Length } -Descending |
            Where-Object { @(Get-ChildItem -LiteralPath $_.FullName -Force).Count -eq 0 } | Remove-Item -Force
    }

    # The release manifest and its signature.
    $sig = $manifestPath + '.sig'
    $destManifest = Join-Path $assets 'manifest.json'
    $same = (Test-Path -LiteralPath $destManifest) -and
        ((Resolve-Path -LiteralPath $destManifest).ProviderPath -eq $manifestPath)
    if (-not $same) {
        if (-not (Test-Path -LiteralPath $sig)) {
            Remove-Item -LiteralPath (Join-Path $assets 'manifest.json.sig') -Force -ErrorAction SilentlyContinue
            Write-Warn 'the manifest has no signature file (manifest.json.sig); the drive will check staged files against the manifest built into it instead'
        }
        foreach ($pair in @(@($manifestPath, 'manifest.json'), @($sig, 'manifest.json.sig'))) {
            if (-not (Test-Path -LiteralPath $pair[0])) { continue }
            $tmp = Join-Path $assets ($pair[1] + $TmpSuffix)
            Copy-Item -LiteralPath $pair[0] -Destination $tmp -Force
            Move-Replace $tmp (Join-Path $assets $pair[1])
        }
    }

    $fileRows = @()
    foreach ($i in ($items | Sort-Object { [string]$_.Entry.id })) {
        if ($failures -contains [string]$i.Entry.id) { continue }
        $fileRows += [ordered]@{ id = [string]$i.Entry.id; sha256 = $i.Sha; staged_at = $i.StagedAt
            target = [string]$i.Entry.target; verify = [string]$i.Entry.verify }
    }
    $skipRows = @()
    foreach ($k in ($skipped.Keys | Sort-Object)) { $skipRows += [ordered]@{ id = $k; reason = $skipped[$k] } }
    $features = $prof.Features
    if ($null -eq $features) { $features = [ordered]@{} }
    $doc = [ordered]@{
        case_defaults = [ordered]@{ agency = $Agency; case_id_prefix = $CasePrefix; examiner = $Examiner }
        features      = $features
        fetcher       = "fetch-assets.ps1 $FetcherVersion"
        files         = $fileRows
        profile       = $prof.Name
        schema        = 1
        skipped       = $skipRows
        staged_at     = $now
    }
    Write-FileAtomic (Join-Path $assets 'profile.json') ((ConvertTo-SortedJson $doc) + "`n")
    Write-Say ("wrote profile.json: {0} file(s) staged, {1} skipped" -f $fileRows.Count, $skipRows.Count)
    if ($failures.Count -gt 0) {
        [Console]::Error.WriteLine(("fetch-assets: {0} file(s) failed ({1}). The rest are staged. Rerun the same command to resume." -f
                $failures.Count, ($failures -join ', ')))
        return 1
    }
    Write-Say 'done. Safely eject the drive (Eject in File Explorer), then boot it; it sets itself up offline.'
    return 0
}

try {
    $rc = Invoke-Fetch
    exit $rc
} catch [UsageError] {
    [Console]::Error.WriteLine("fetch-assets: $($_.Exception.Message)")
    exit 2
} catch {
    [Console]::Error.WriteLine("fetch-assets: $($_.Exception.Message) Rerun the same command to resume; report it if it keeps happening.")
    exit 1
}
