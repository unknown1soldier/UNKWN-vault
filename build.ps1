# Complete UNKNWN build and release entry point. Run: .\build.ps1
# Automated inputs: UNKNWN_CERT_THUMBPRINT and UNKNWN_KEY_PASS.
# -Dev retains the unsigned, clearly labeled development build.
param(
    [switch]$Dev,
    [switch]$CleanGenerated,
    [int]$Build = 1,
    [string]$Thumbprint = $env:UNKNWN_CERT_THUMBPRINT,
    [string]$Timestamp = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:CurrentStage = "Preflight"
$script:ExitCode = 1
$script:Failed = $false
$script:FailureMessage = ""
$script:Summary = [ordered]@{
    "PRECHECK" = "NOT RUN"
    "ICON" = "NOT RUN"
    "TESTS" = "NOT RUN"
    "COMPILE" = "NOT RUN"
    "MANIFEST" = "NOT RUN"
    "SIGNATURE" = "NOT RUN"
    "VERIFY" = "NOT RUN"
    "INSTALL VERIFY" = "NOT RUN"
    "PACKAGE" = "NOT RUN"
}
$originalKeyPass = [Environment]::GetEnvironmentVariable("UNKNWN_KEY_PASS", "Process")
$keyPassValue = $null
$root = $PSScriptRoot
$dist = $null
$exe = $null
$archive = $null
$archiveStage = $null
$python = $null
$iconPath = $null
$iconEmbedded = $false
$thumb = $null
$expectedPublicKey = $null
$nuitkaBuild = $null
$debugBatch = $null

function Write-Stage([int]$Number, [string]$Name) {
    $script:CurrentStage = $Name
    Write-Host ""
    Write-Host "[$Number/7] $Name" -ForegroundColor Cyan
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments, [string]$FailureText) {
    & $FilePath @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $script:ExitCode = $code
        throw "$FailureText (exit code $code)"
    }
}

function Assert-PathUnderRoot([string]$Path, [string]$Description) {
    $full = [IO.Path]::GetFullPath($Path)
    $base = [IO.Path]::GetFullPath($root).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify $Description outside the project root: $full"
    }
    $cursor = $root
    $relative = $full.Substring($base.Length)
    foreach ($part in $relative.Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)) {
        $cursor = Join-Path $cursor $part
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to modify $Description through a symbolic link or junction: $cursor"
            }
        }
    }
    return $full
}

function Remove-GeneratedDirectory([string]$Path, [string]$Description) {
    $full = Assert-PathUnderRoot $Path $Description
    if (Test-Path -LiteralPath $full) {
        if (-not (Test-Path -LiteralPath $full -PathType Container)) {
            throw "Expected generated directory for $Description, found another item: $full"
        }
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

function Test-IcoFile([string]$Path) {
    $iconName = Split-Path -Leaf $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required application icon is missing: $Path. Place app.ico or UNKNWN.ico in the project root before building."
    }
    [byte[]]$bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 22 -or
        [BitConverter]::ToUInt16($bytes, 0) -ne 0 -or
        [BitConverter]::ToUInt16($bytes, 2) -ne 1) {
        throw "$iconName is not a valid Windows ICO container. Place a valid .ico file in the project root."
    }
    $count = [BitConverter]::ToUInt16($bytes, 4)
    $tableEnd = 6 + (16 * [int]$count)
    if ($count -lt 1 -or $tableEnd -gt $bytes.Length) {
        throw "$iconName has an invalid or truncated image directory. Replace it with a valid Windows .ico file in the project root."
    }
    for ($i = 0; $i -lt $count; $i++) {
        $entry = 6 + (16 * $i)
        if ($bytes[$entry + 3] -ne 0) {
            throw "$iconName contains an invalid reserved directory byte. Replace it with a valid Windows .ico file in the project root."
        }
        $size = [BitConverter]::ToUInt32($bytes, $entry + 8)
        $offset = [BitConverter]::ToUInt32($bytes, $entry + 12)
        $end = [long]$offset + [long]$size
        if ($size -lt 8 -or $offset -lt $tableEnd -or $end -gt $bytes.Length) {
            throw "$iconName contains an invalid or truncated image entry. Replace it with a valid Windows .ico file in the project root."
        }
        $imageOffset = [int]$offset
        $png = $size -ge 8 -and
            $bytes[$imageOffset] -eq 0x89 -and $bytes[$imageOffset + 1] -eq 0x50 -and
            $bytes[$imageOffset + 2] -eq 0x4e -and $bytes[$imageOffset + 3] -eq 0x47 -and
            $bytes[$imageOffset + 4] -eq 0x0d -and $bytes[$imageOffset + 5] -eq 0x0a -and
            $bytes[$imageOffset + 6] -eq 0x1a -and $bytes[$imageOffset + 7] -eq 0x0a
        $dibHeader = if ($size -ge 4) { [BitConverter]::ToUInt32($bytes, $imageOffset) } else { 0 }
        if (-not $png -and ($dibHeader -lt 12 -or $dibHeader -gt $size)) {
            throw "$iconName contains an unsupported or invalid image entry. Use a valid Windows .ico file in the project root."
        }
    }
    $icon = $null
    $bitmap = $null
    try {
        Add-Type -AssemblyName System.Drawing
        $icon = New-Object System.Drawing.Icon($Path)
        $bitmap = $icon.ToBitmap()
        if ($bitmap.Width -lt 1 -or $bitmap.Height -lt 1) {
            throw "Windows decoded $iconName without a usable image."
        }
    } catch {
        throw "Windows could not decode $iconName as a usable icon. Replace it with a valid Windows .ico file in the project root."
    } finally {
        if ($bitmap) { $bitmap.Dispose() }
        if ($icon) { $icon.Dispose() }
    }
}

function Find-SignTool {
    $command = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kits -PathType Container) {
        $found = Get-ChildItem -LiteralPath $kits -Filter "signtool.exe" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Directory.Name -eq "x64" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

function Get-CodeSigningCertificate([string]$Thumb) {
    foreach ($store in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
        if (-not (Test-Path -LiteralPath $store)) { continue }
        $cert = Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue |
            Where-Object { $_ -and $_.Thumbprint -eq $Thumb } |
            Select-Object -First 1
        if (-not $cert) { continue }
        if (-not $cert.HasPrivateKey) { throw "Certificate $Thumb is installed but has no accessible private key." }
        $now = Get-Date
        if ($now -lt $cert.NotBefore -or $now -gt $cert.NotAfter) {
            throw "Certificate $Thumb is not currently valid (validity: $($cert.NotBefore) through $($cert.NotAfter))."
        }

        $ekuExtension = $cert.Extensions |
            Where-Object {
                $_ -and $_.GetType().FullName -eq "System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension"
            } |
            Select-Object -First 1

        if ($ekuExtension) {
            $oids = @(
                $ekuExtension.EnhancedKeyUsages |
                    ForEach-Object {
                        if ($null -ne $_ -and $null -ne $_.Value) { $_.Value }
                    } |
                    Where-Object { $_ }
            )
            if ($oids.Count -gt 0 -and "1.3.6.1.5.5.7.3.3" -notin $oids) {
                throw "Certificate $Thumb is not permitted for code signing."
            }
        }
        return $cert
    }
    throw "No certificate with thumbprint $Thumb and a private key was found in CurrentUser\My or LocalMachine\My."
}

function Test-WritableDirectory([string]$Path) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    $probe = Join-Path $Path (".unknwn-write-test-" + [guid]::NewGuid().ToString("N"))
    try {
        [IO.File]::WriteAllText($probe, "write-test")
    } finally {
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
    }
}

try {
    Write-Stage 1 "Preflight"
    if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "Could not resolve the directory containing build.ps1."
    }
    Set-Location -LiteralPath $root
    if ($Build -lt 1 -or $Build -gt 65535) {
        throw "Build number must be between 1 and 65535 for the Windows file/product version."
    }

    $required = @(
        "unknwn.py", "unknwn_integrity.py", "unknwn_media.py", "warden_art.py", "operation_engine.py", "easter_eggs.py",
        "easter_egg_messages.py", "assets\uwu_kawaii.jpg",
        "requirements.txt", "tools\release.py", "verify_install.ps1", "tests\test_core.py",
        "tests\test_media.py", "tests\test_diagnostics.py", "tests\test_viewer_flow.py",
        "tests\test_vault_management.py", "tests\test_vault_management_move.py", "tests\test_release.py",
        "tests\test_operation_engine.py", "tests\test_easter_eggs.py"
    )
    foreach ($relative in $required) {
        $path = Join-Path $root $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required project file is missing: $path"
        }
    }
    $releaseTool = Join-Path $root "tools\release.py"
    $integrityModule = Join-Path $root "unknwn_integrity.py"
    $buildDir = Join-Path $root "build"
    $distRoot = Join-Path $root "dist"
    $src = Join-Path $buildDir "src"
    $dist = Join-Path $distRoot "unknwn.dist"
    $exe = Join-Path $dist "UNKNWN.exe"
    $archive = Join-Path $root "UNKNWN-build$Build.zip"
    if (-not $Dev) {
        $checksumPath = "$archive.sha256"
        if ((Test-Path -LiteralPath $archive) -or (Test-Path -LiteralPath $checksumPath)) {
            throw "Release output for build $Build already exists. Choose a new -Build number; existing release artifacts are never overwritten."
        }
        $archiveStage = Join-Path $root (".UNKNWN-build$Build-" + [guid]::NewGuid().ToString("N") + ".staging.zip")
        $null = Assert-PathUnderRoot $archiveStage "staged release package"
    }
    $appIcon = Join-Path $root "app.ico"
    $namedIcon = Join-Path $root "UNKNWN.ico"
    if (Test-Path -LiteralPath $appIcon -PathType Leaf) {
        $iconPath = [IO.Path]::GetFullPath($appIcon)
    } elseif (Test-Path -LiteralPath $namedIcon -PathType Leaf) {
        $iconPath = [IO.Path]::GetFullPath($namedIcon)
    } else {
        $iconPath = [IO.Path]::GetFullPath($appIcon)
    }
    Test-IcoFile $iconPath
    $script:Summary["ICON"] = "PASS (ICO input validated)"

    if (-not $Dev) {
        $privateKey = Join-Path $root "release_key.pem"
        $publicKey = Join-Path $root "release_pubkey.txt"
        if (-not (Test-Path -LiteralPath $privateKey -PathType Leaf) -or
            -not (Test-Path -LiteralPath $publicKey -PathType Leaf)) {
            if (-not (Test-Path -LiteralPath $privateKey) -and -not (Test-Path -LiteralPath $publicKey)) {
                throw "Release signing keys are missing. Create the release identity once, deliberately, with: python tools\release.py keygen. Back up release_key.pem offline; do not delete or replace an existing release identity."
            }
            throw "The release key pair is incomplete. Restore the matching release_key.pem and release_pubkey.txt from the protected release-key backup; the build will not generate or replace either key."
        }
        $publicHex = (Get-Content -LiteralPath $publicKey -Raw).Trim()
        if ($publicHex -cnotmatch "^[0-9a-fA-F]{64}$") {
            throw "release_pubkey.txt must contain exactly 64 hexadecimal characters (the raw Ed25519 public key). Restore the configured public key; it will not be replaced automatically."
        }
        $expectedPublicKey = $publicHex.ToLowerInvariant()
        $integrityText = Get-Content -LiteralPath $integrityModule -Raw
        if ($integrityText -notmatch '(?m)^RELEASE_PUBKEY\s*=\s*"[0-9a-fA-F]{64}"') {
            throw "unknwn_integrity.py does not contain a configured 64-character release public key."
        }

        if (-not $Thumbprint) { $Thumbprint = Read-Host "Code-signing certificate Thumbprint" }
        $thumb = ($Thumbprint -replace "\s", "").ToUpperInvariant()
        if ($thumb -notmatch "^[0-9A-F]{40}$") {
            throw "A 40-character SHA-1 certificate thumbprint is required. Set UNKNWN_CERT_THUMBPRINT or provide -Thumbprint."
        }
        $signtool = Find-SignTool
        if (-not $signtool) {
            throw "signtool.exe is missing. Install the Windows 10/11 SDK (Signing Tools) and ensure signtool.exe is discoverable."
        }
        $null = Get-CodeSigningCertificate $thumb

        if (-not $env:UNKNWN_KEY_PASS) {
            $securePass = Read-Host "ReleaseKey passphrase" -AsSecureString
            $bstr = [IntPtr]::Zero
            try {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass)
                $keyPassValue = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            } finally {
                if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                if ($securePass) { $securePass.Dispose() }
            }
            if (-not $keyPassValue) { throw "A non-empty ReleaseKey passphrase is required." }
            [Environment]::SetEnvironmentVariable("UNKNWN_KEY_PASS", $keyPassValue, "Process")
        } else {
            $keyPassValue = $env:UNKNWN_KEY_PASS
        }

        $python = Join-Path $root ".venv\Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
            $pythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
            if (-not $pythonCommand) { throw "Python is missing. Create the project virtual environment or install Python and add python.exe to PATH." }
            $python = $pythonCommand.Source
        }
        Invoke-Checked $python @($releaseTool, "validate-key", "--key", $privateKey, "--pub", $publicKey) "Release key validation failed"
        [Environment]::SetEnvironmentVariable("UNKNWN_KEY_PASS", $null, "Process")
    } else {
        $python = Join-Path $root ".venv\Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
            $pythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
            if (-not $pythonCommand) { throw "Python is missing. Create the project virtual environment or install Python and add python.exe to PATH." }
            $python = $pythonCommand.Source
        }
    }

    $versionOutput = & $python -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Python could not start: $($versionOutput -join ' ')" }
    Write-Host "Python: $($versionOutput -join ' ') ($python)"

    $dependencyCode = "import importlib.util, sys; required={'PyQt5':'PyQt5','cryptography':'cryptography','PyMuPDF':'pymupdf','py7zr':'py7zr','rarfile':'rarfile','Nuitka':'nuitka'}; missing=[label for label,module in required.items() if importlib.util.find_spec(module) is None]; print('Missing: ' + ', '.join(missing)) if missing else print('All required Python packages are installed'); sys.exit(bool(missing))"
    $dependencyOutput = & $python -c $dependencyCode 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Required Python packages are unavailable: $($dependencyOutput -join ' '). Install them with: $python -m pip install -r requirements.txt nuitka"
    }
    Write-Host ($dependencyOutput -join " ")

    $pymupdfPackageOutput = & $python -c "import importlib.util, sys; spec=importlib.util.find_spec('pymupdf'); paths=list(spec.submodule_search_locations or ()) if spec else []; print(paths[0] if paths else '')" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not locate the installed PyMuPDF package: $($pymupdfPackageOutput -join ' ')"
    }
    $pymupdfPackage = ($pymupdfPackageOutput -join " ").Trim()
    if (-not $pymupdfPackage) { throw "Could not locate the installed PyMuPDF package." }
    $pymupdfWrapper = Join-Path $pymupdfPackage "mupdf.py"
    $pymupdfExtension = Join-Path $pymupdfPackage "_mupdf.pyd"
    $pymupdfNativeDll = Join-Path $pymupdfPackage "mupdfcpp64.dll"
    foreach ($runtimeFile in @($pymupdfWrapper, $pymupdfExtension, $pymupdfNativeDll)) {
        if (-not (Test-Path -LiteralPath $runtimeFile -PathType Leaf)) {
            throw "Required PyMuPDF standalone runtime file is missing: $runtimeFile"
        }
    }

    $nuitkaVersion = & $python -m nuitka --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Nuitka is installed but could not report its version: $($nuitkaVersion -join ' ')" }
    Write-Host "Nuitka: $($nuitkaVersion -join ' ')"

    $msvcCommand = Get-Command "cl.exe" -ErrorAction SilentlyContinue
    $msvcAvailable = [bool]$msvcCommand
    $vswherePaths = @()
    if (${env:ProgramFiles(x86)}) {
        $vswherePaths += Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    }
    if ($env:ProgramFiles) {
        $vswherePaths += Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe"
    }
    foreach ($vswherePath in $vswherePaths) {
        if (-not (Test-Path -LiteralPath $vswherePath -PathType Leaf)) { continue }
        $msvcInstallations = @(& $vswherePath -products "*" -requires "Microsoft.VisualStudio.Component.VC.Tools.x86.x64" -property installationPath 2>$null)
        if ($LASTEXITCODE -eq 0 -and $msvcInstallations.Count -gt 0) {
            $msvcAvailable = $true
            break
        }
    }
    if (-not $msvcAvailable) {
        throw "Visual Studio C++ Build Tools (MSVC x86/x64) are required. Install the Visual Studio Build Tools C++ workload; this build does not fall back to the exceptionally slow Zig compilation of PyMuPDF."
    }
    $compiler = "MSVC (latest)"
    Write-Host "Compiler: $compiler"

    $buildDir = Join-Path $root "build"
    $distRoot = Join-Path $root "dist"
    $src = Join-Path $buildDir "src"
    $nuitkaBuild = Join-Path $distRoot "unknwn.build"
    $dist = Join-Path $distRoot "unknwn.dist"
    $exe = Join-Path $dist "UNKNWN.exe"
    $archive = Join-Path $root "UNKNWN-build$Build.zip"
    $null = Assert-PathUnderRoot (Join-Path $buildDir ".write-check") "build output"
    $null = Assert-PathUnderRoot (Join-Path $distRoot ".write-check") "distribution output"
    Test-WritableDirectory $root
    Test-WritableDirectory $buildDir
    Test-WritableDirectory $distRoot
    if (Test-Path -LiteralPath $dist) {
        throw "The existing distribution is protected and will not be removed or overwritten: $dist. Move or back it up before building."
    }
    if (-not $Dev -and (
        (Test-Path -LiteralPath $archive) -or
        (Test-Path -LiteralPath ($archive + ".sha256"))
    )) {
        throw "The target release archive or checksum already exists and will not be overwritten. Choose another -Build number or move the existing files."
    }
    $generatedDirectories = @(
        @($src, $nuitkaBuild) | Where-Object { Test-Path -LiteralPath $_ }
    )
    if ($generatedDirectories.Count -gt 0 -and -not $CleanGenerated) {
        throw "Generated build inputs already exist and are preserved by default: $($generatedDirectories -join ', '). Re-run with -CleanGenerated only if these generated directories may be removed."
    }
    $script:Summary["PRECHECK"] = "PASS"
    Write-Host "Project, keys/configuration, dependencies, compiler, signing setup, and output paths validated."

    if ($CleanGenerated) {
        Remove-GeneratedDirectory $src "staged build sources"
        Remove-GeneratedDirectory $nuitkaBuild "Nuitka build cache"
        Write-Host "Explicit -CleanGenerated: removed only the validated staged source and Nuitka cache directories."
    }
    $debugScript = Join-Path $nuitkaBuild "scons-debug.py"
    $debugBatch = Join-Path $nuitkaBuild "scons-debug.bat"
    $null = Assert-PathUnderRoot $debugScript "Nuitka debug script"
    if (Test-Path -LiteralPath $debugScript -PathType Leaf) {
        Remove-Item -LiteralPath $debugScript -Force
    }
    if (Test-Path -LiteralPath $debugBatch -PathType Leaf) {
        Remove-Item -LiteralPath $debugBatch -Force
    }
    Write-Stage 2 "Security Tests"
    $oldQtPlatform = $env:QT_QPA_PLATFORM
    $env:QT_QPA_PLATFORM = "offscreen"
    try {
        Invoke-Checked $python @(
            "-m", "unittest",
            "tests.test_media",
            "tests.test_diagnostics",
            "tests.test_operation_engine",
            "tests.test_viewer_flow",
            "tests.test_vault_management",
            "tests.test_vault_management_move",
            "tests.test_core",
            "tests.test_release",
            "tests.test_easter_eggs"
        ) "Security/unit/release tests failed"
    } finally {
        $env:QT_QPA_PLATFORM = $oldQtPlatform
    }
    $script:Summary["TESTS"] = "PASS"

    Write-Stage 3 "Compile"
    New-Item -Path $src -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath @(
        (Join-Path $root "unknwn.py"),
        (Join-Path $root "unknwn_integrity.py"),
        (Join-Path $root "unknwn_media.py"),
        (Join-Path $root "warden_art.py"),
        (Join-Path $root "operation_engine.py"),
        (Join-Path $root "easter_eggs.py"),
        (Join-Path $root "easter_egg_messages.py")
    ) -Destination $src
    $stagedAssets = Join-Path $src "assets"
    New-Item -Path $stagedAssets -ItemType Directory -Force | Out-Null
    $bundledImages = @(
        @{ Source = (Join-Path $root "assets\im_tired.jpg"); Name = "im_tired.jpg"; Description = "I'm Tired theme" },
        @{ Source = (Join-Path $root "assets\meow.jpg"); Name = "meow.jpg"; Description = "M-E-O-W easter egg" },
        @{ Source = (Join-Path $root "assets\uwu_kawaii.jpg"); Name = "uwu_kawaii.jpg"; Description = "UWU KAWAI secret theme" }
    )
    foreach ($image in $bundledImages) {
        if (-not (Test-Path -LiteralPath $image.Source -PathType Leaf)) {
            throw "The $($image.Description) image is missing: $($image.Source)"
        }
        $stagedImage = Join-Path $stagedAssets $image.Name
        Copy-Item -LiteralPath $image.Source -Destination $stagedImage -Force
        $sourceHash = (Get-FileHash -LiteralPath $image.Source -Algorithm SHA256).Hash
        $stagedHash = (Get-FileHash -LiteralPath $stagedImage -Algorithm SHA256).Hash
        if ($sourceHash -ne $stagedHash) {
            throw "The staged $($image.Description) image did not match its source: $stagedImage"
        }
    }
    $stagedApp = Join-Path $src "unknwn.py"
    if ($Dev) {
        $sourceText = [IO.File]::ReadAllText($stagedApp)
        $devMarkerPattern = '(?m)^DEV_BUILD = False(?=[ \t]*(?:#|$))'
        if ([regex]::Matches($sourceText, $devMarkerPattern).Count -ne 1) {
            throw "Expected exactly one explicit DEV_BUILD = False marker in staged source."
        }
        $sourceText = [regex]::Replace($sourceText, $devMarkerPattern, 'DEV_BUILD = True')
        if ($sourceText -notmatch '(?m)^DEV_BUILD = True(?=[ \t]*(?:#|$))') {
            throw "Could not enable the explicit DEV_BUILD marker in staged source."
        }
        [IO.File]::WriteAllText($stagedApp, $sourceText, (New-Object Text.UTF8Encoding $false))
    } else {
        Invoke-Checked $python @($releaseTool, "embed", "--module", (Join-Path $src "unknwn_integrity.py"), "--pub", (Join-Path $root "release_pubkey.txt")) "Embedding the configured release public key failed"
        $stagedIntegrity = Get-Content -LiteralPath (Join-Path $src "unknwn_integrity.py") -Raw
        if ($stagedIntegrity -notmatch ('(?m)^RELEASE_PUBKEY\s*=\s*"' + [regex]::Escape($expectedPublicKey) + '"')) {
            throw "Staged unknwn_integrity.py does not contain the configured release public key."
        }
    }
    $console = if ($Dev) { "force" } else { "disable" }
    # Prefer Clang when available while keeping MSVC as the required fallback.
    $useClang = $false
    $clangCmd = Get-Command "clang-cl.exe" -ErrorAction SilentlyContinue
    if ($clangCmd) {
        $useClang = $true
        Write-Host "Clang (clang-cl) found on PATH: $($clangCmd.Source)"
    } else {
        $vswherePaths = @()
        if (${env:ProgramFiles(x86)}) { $vswherePaths += Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe" }
        if ($env:ProgramFiles) { $vswherePaths += Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe" }
        foreach ($vswherePath in $vswherePaths) {
            if (-not (Test-Path -LiteralPath $vswherePath -PathType Leaf)) { continue }
            $installs = @(& $vswherePath -products '*' -requires "Microsoft.VisualStudio.Component.VC.Tools.x86.x64" -property installationPath 2>$null)
            foreach ($inst in $installs) {
                $clangDirCandidates = @(
                    (Join-Path $inst "VC\Tools\Llvm\x64\bin"),
                    (Join-Path $inst "VC\Tools\Llvm\bin"),
                    (Join-Path $inst "VC\Tools\Llvm\ARM64\bin")
                )
                foreach ($cd in $clangDirCandidates) {
                    if (Test-Path (Join-Path $cd "clang-cl.exe")) {
                        $useClang = $true
                        Write-Host "Clang (clang-cl) found at: $cd"
                        break
                    }
                }
                if ($useClang) { break }
            }
            if ($useClang) { break }
        }
    }

    if ($useClang) {
        Write-Host "Enabling Nuitka --clang (will prefer Clang toolchain)."
    } else {
        Write-Host "Clang is not installed; MSVC will compile the remaining modules normally while the large PyMuPDF wrapper is shipped externally."
    }

    $nuitkaArgs = @(
        "-m", "nuitka", "--standalone", "--enable-plugin=pyqt5", "--windows-console-mode=$console",
        "--windows-icon-from-ico=$iconPath",
        "--nofollow-import-to=pymupdf.mupdf",
        "--include-data-files=$pymupdfWrapper=mupdf.py",
        "--include-data-files=$pymupdfExtension=_mupdf.pyd",
        "--include-data-files=$pymupdfNativeDll=pymupdf/mupdfcpp64.dll",
        "--include-data-dir=$stagedAssets=assets",
        "--include-package=py7zr",
        "--include-module=rarfile",
        "--include-qt-plugins=imageformats,mediaservice,audio,playlistformats,iconengines",
        "--product-name=UNKNWN", "--file-description=UNKNWN", "--file-version=1.0.0.$Build",
        "--product-version=1.0.0.$Build", "--output-dir=$distRoot", "--output-filename=UNKNWN.exe",
        "--msvc=latest", "--lto=no", "--python-flag=no_asserts", "--python-flag=no_docstrings",
        "--assume-yes-for-downloads",
        $stagedApp
    )

    if ($useClang) { $nuitkaArgs += "--clang" }
    Write-Host "Embedding project icon into UNKNWN.exe: $iconPath"
    Write-Host "Nuitka compilation started with the detected compiler. PyMuPDF's generated wrapper is shipped as an external module to avoid compiling its large translation unit."
    $compileTimer = [Diagnostics.Stopwatch]::StartNew()
    Push-Location -LiteralPath $src
    try {
        Invoke-Checked $python $nuitkaArgs "Nuitka compilation or icon embedding failed"
    } finally {
        Pop-Location
        $compileTimer.Stop()
        Write-Host ("Compile elapsed: {0:hh\:mm\:ss}" -f $compileTimer.Elapsed)
    }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Nuitka completed without producing the expected executable: $exe" }
    if (-not $Dev) {
        Invoke-Checked $python @($releaseTool, "verify-embedded-key", "--exe", $exe, "--pub", (Join-Path $root "release_pubkey.txt")) "Compiled executable release-key validation failed"
    }
    $iconApi = @"
using System;
using System.Runtime.InteropServices;
public static class UnknwnIconResourceCheck {
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern uint ExtractIconEx(string file, int index, IntPtr[] large, IntPtr[] small, uint count);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyIcon(IntPtr icon);
}
"@
    if (-not ("UnknwnIconResourceCheck" -as [type])) { Add-Type -TypeDefinition $iconApi }
    [IntPtr[]]$largeIcon = @([IntPtr]::Zero)
    [IntPtr[]]$smallIcon = @([IntPtr]::Zero)
    $embeddedCount = [UnknwnIconResourceCheck]::ExtractIconEx($exe, 0, $largeIcon, $smallIcon, 1)
    try {
        if ($embeddedCount -lt 1 -or ($largeIcon[0] -eq [IntPtr]::Zero -and $smallIcon[0] -eq [IntPtr]::Zero)) {
            throw "The compiled UNKNWN.exe has no extractable embedded Windows icon resource. Nuitka did not apply $([IO.Path]::GetFileName($iconPath))."
        }
    } finally {
        if ($largeIcon[0] -ne [IntPtr]::Zero) { [void][UnknwnIconResourceCheck]::DestroyIcon($largeIcon[0]) }
        if ($smallIcon[0] -ne [IntPtr]::Zero) { [void][UnknwnIconResourceCheck]::DestroyIcon($smallIcon[0]) }
    }
    $iconEmbedded = $true
    $script:Summary["ICON"] = "PASS (validated and embedded)"
    Write-Host "Embedded icon verified in UNKNWN.exe."
    $executables = @(Get-ChildItem -LiteralPath $dist -Recurse -File | Where-Object { $_.Extension -eq ".exe" })
    if ($executables.Count -ne 1 -or $executables[0].FullName -ne $exe) {
        throw "Unexpected executable content was found in the standalone distribution; expected only $exe."
    }
    $libraries = @(Get-ChildItem -LiteralPath $dist -Recurse -File | Where-Object { $_.Extension -in @(".dll", ".pyd") })
    if ($libraries.Count -lt 1) { throw "The standalone distribution contains no DLL/PYD runtime files: $dist" }
    $script:Summary["COMPILE"] = "PASS"
    Write-Host "Executable: $exe"

    if ($Dev) {
        $script:Summary["MANIFEST"] = "SKIPPED (development build)"
        $script:Summary["SIGNATURE"] = "SKIPPED (development build)"
        $script:Summary["VERIFY"] = "SKIPPED (development build)"
        $script:Summary["INSTALL VERIFY"] = "SKIPPED (development build)"
        $script:Summary["PACKAGE"] = "SKIPPED (development build)"
    } else {
        Write-Stage 4 "Release Manifest"
        Invoke-Checked $signtool @("sign", "/sha1", $thumb, "/fd", "SHA256", "/tr", $Timestamp, "/td", "SHA256", "/d", "UNKNWN", $exe) "Authenticode signing failed"
        $auth = Get-AuthenticodeSignature -LiteralPath $exe
        if ($auth.Status -ne "Valid" -or $auth.SignerCertificate.Thumbprint -ne $thumb) {
            throw "Authenticode verification failed after signing (status: $($auth.Status)); expected signer $thumb."
        }
        if ($null -eq $auth.TimeStamperCertificate) { throw "Authenticode signature has no trusted timestamp. The release will not be packaged." }
        $script:Summary["SIGNATURE"] = "PASS"
        $previousPass = [Environment]::GetEnvironmentVariable("UNKNWN_KEY_PASS", "Process")
        try {
            if ($keyPassValue) { [Environment]::SetEnvironmentVariable("UNKNWN_KEY_PASS", $keyPassValue, "Process") }
            Invoke-Checked $python @($releaseTool, "manifest", "--dist", $dist, "--key", (Join-Path $root "release_key.pem"), "--build", "$Build") "Release manifest generation/signing failed"
        } finally {
            [Environment]::SetEnvironmentVariable("UNKNWN_KEY_PASS", $previousPass, "Process")
        }
        $manifestPath = Join-Path $dist "unknwn.manifest"
        $signaturePath = Join-Path $dist "unknwn.manifest.sig"
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) {
            throw "Release manifest or Ed25519 signature was not produced."
        }
        $script:Summary["MANIFEST"] = "PASS"

        Write-Stage 5 "Integrity Verification"
        Invoke-Checked $python @($releaseTool, "verify", "--dist", $dist, "--pub", (Join-Path $root "release_pubkey.txt")) "Release integrity/signature verification failed"
        $script:Summary["VERIFY"] = "PASS"

        Write-Stage 6 "Installation Verification"
        $powershellCommand = Get-Command "powershell.exe" -ErrorAction SilentlyContinue
        if (-not $powershellCommand) { throw "Windows PowerShell is unavailable to run verify_install.ps1." }
        Invoke-Checked $powershellCommand.Source @(
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
            (Join-Path $root "verify_install.ps1"), "-Dir", $dist, "-ExpectedThumbprint", $thumb
        ) "Installation Authenticode verification failed"
        $script:Summary["INSTALL VERIFY"] = "PASS"

        Write-Stage 7 "Final Validation"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory(
            $dist, $archiveStage, [IO.Compression.CompressionLevel]::Optimal, $false
        )
        if (-not (Test-Path -LiteralPath $archiveStage -PathType Leaf) -or (Get-Item -LiteralPath $archiveStage).Length -le 0) {
            throw "The staged release archive was not created or is empty."
        }
        Invoke-Checked $python @($releaseTool, "verify-archive", "--archive", $archiveStage, "--dist", $dist, "--pub", (Join-Path $root "release_pubkey.txt")) "Release archive verification failed"
        [IO.File]::Move($archiveStage, $archive)
        $checksum = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        $checksumPath = "$archive.sha256"
        $checksumBytes = (New-Object Text.UTF8Encoding $false).GetBytes(
            "$checksum  $(Split-Path -Leaf $archive)`r`n"
        )
        $checksumStream = [IO.File]::Open(
            $checksumPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        try {
            $checksumStream.Write($checksumBytes, 0, $checksumBytes.Length)
            $checksumStream.Flush($true)
        } finally {
            $checksumStream.Dispose()
        }
        if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) { throw "The release archive checksum was not written." }
        Invoke-Checked $python @($releaseTool, "verify-archive", "--archive", $archive, "--dist", $dist, "--pub", (Join-Path $root "release_pubkey.txt")) "Published release archive verification failed"
        $script:Summary["PACKAGE"] = "PASS"
    }
} catch {
    $script:Failed = $true
    $script:FailureMessage = $_.Exception.Message
    if ($script:ExitCode -eq 1 -and $script:CurrentStage -eq "Preflight") { $script:Summary["PRECHECK"] = "FAIL" }
    switch -Regex ($script:CurrentStage) {
        "^Preflight$" { $script:Summary["PRECHECK"] = "FAIL"; break }
        "^Security Tests$" { $script:Summary["TESTS"] = "FAIL"; break }
        "^Compile$" { $script:Summary["COMPILE"] = "FAIL"; break }
        "^Release Manifest$" {
            if ($script:Summary["SIGNATURE"] -ne "PASS") { $script:Summary["SIGNATURE"] = "FAIL" }
            elseif ($script:Summary["MANIFEST"] -ne "PASS") { $script:Summary["MANIFEST"] = "FAIL" }
            break
        }
        "^Integrity Verification$" { $script:Summary["VERIFY"] = "FAIL"; break }
        "^Installation Verification$" { $script:Summary["INSTALL VERIFY"] = "FAIL"; break }
        "^Final Validation$" { $script:Summary["PACKAGE"] = "FAIL"; break }
    }
    Write-Host ""
    Write-Host "FAILED STAGE: $script:CurrentStage" -ForegroundColor Red
    Write-Host $script:FailureMessage -ForegroundColor Red
} finally {
    $debugScript = if ($nuitkaBuild) { Join-Path $nuitkaBuild "scons-debug.py" } else { $null }
    if ($debugScript -and (Test-Path -LiteralPath $debugScript -PathType Leaf)) {
        try {
            Remove-Item -LiteralPath $debugScript -Force
            Write-Host "Removed generated SCons debug script (it can serialize the compiler environment)."
        } catch {
            $script:Failed = $true
            $script:FailureMessage = "Could not remove generated SCons debug script; inspect and delete it manually: $debugScript"
            Write-Host $script:FailureMessage -ForegroundColor Red
        }
    }
    if ($debugBatch -and (Test-Path -LiteralPath $debugBatch -PathType Leaf)) {
        try {
            Remove-Item -LiteralPath $debugBatch -Force
        } catch {
            $script:Failed = $true
            $script:FailureMessage = "Could not remove generated SCons debug launcher: $debugBatch"
            Write-Host $script:FailureMessage -ForegroundColor Red
        }
    }
    if ($archiveStage -and (Test-Path -LiteralPath $archiveStage -PathType Leaf)) {
        try {
            Remove-Item -LiteralPath $archiveStage -Force
        } catch {
            $script:Failed = $true
            $script:FailureMessage = "Could not remove the unverified staged release archive; inspect and delete it manually: $archiveStage"
            Write-Host $script:FailureMessage -ForegroundColor Red
        }
    }
    [Environment]::SetEnvironmentVariable("UNKNWN_KEY_PASS", $originalKeyPass, "Process")
    $keyPassValue = $null
}

Write-Host ""
Write-Host "================ UNKNWN RELEASE SUMMARY ================" -ForegroundColor Cyan
foreach ($entry in $script:Summary.GetEnumerator()) {
    Write-Host ("{0}: {1}" -f $entry.Key, $entry.Value)
}
if ($iconPath) { Write-Host "ICON OPTION: --windows-icon-from-ico=$iconPath" }
Write-Host ("ICON EMBEDDED: {0}" -f $(if ($iconEmbedded) { "VERIFIED" } else { "NOT VERIFIED" }))
if ($dist) { Write-Host "OUTPUT DIRECTORY: $dist" }
if ($exe) { Write-Host "EXECUTABLE: $exe" }
if (-not $Dev -and $archive) { Write-Host "RELEASE PACKAGE: $archive"; Write-Host "SHA-256: $archive.sha256" }
if ($script:Failed) {
    Write-Host "FINAL RESULT: RELEASE FAILED" -ForegroundColor Red
    exit $script:ExitCode
}
if ($Dev) {
    Write-Host "FINAL RESULT: DEVELOPMENT BUILD READY (NOT FOR DISTRIBUTION)" -ForegroundColor Yellow
} else {
    Write-Host "FINAL RESULT: RELEASE READY" -ForegroundColor Green
}
exit 0
