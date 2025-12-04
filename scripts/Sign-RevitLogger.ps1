[CmdletBinding()]
param(
    [string]$PfxPath = "C:\ProjectX-CodeSign.pfx",
    [string]$PfxPassword = "Meinh@rdt1234!",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$BaseDir,
    [string[]]$Versions = @('Revit2023','Revit2024','Revit2025','Revit2026'),
    [string]$DllName = "ProjectX.dll",
    [switch]$ForceRecreatePfx
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($BaseDir)) {
    Add-Type -AssemblyName System.Windows.Forms
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description = "Select the Base Directory (containing bin folder)"
    $fbd.ShowNewFolderButton = $false
    
    if ($fbd.ShowDialog() -eq 'OK') {
        $BaseDir = $fbd.SelectedPath
    } else {
        Write-Error "No directory selected. Operation cancelled."
        exit 1
    }
}

# --- Self-signed certificate creation & trust for current user ---
$certSubject = "CN=ProjectX Code Signing"
$securePassword = ConvertTo-SecureString -String $PfxPassword -Force -AsPlainText
try {
    if ($ForceRecreatePfx -or -not (Test-Path $PfxPath)) {
        if ($ForceRecreatePfx -and (Test-Path $PfxPath)) { Remove-Item -Path $PfxPath -Force }
        Write-Host "Creating self-signed code signing certificate..." -ForegroundColor Cyan
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $certSubject -CertStoreLocation "Cert:\CurrentUser\My"
        Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $securePassword | Out-Null
        Write-Host "Self-signed code signing certificate exported to $PfxPath" -ForegroundColor Green
    } else {
        Write-Host "PFX file already exists at $PfxPath. Will import into CurrentUser store and trust it." -ForegroundColor Yellow
    }

    # Import the PFX into CurrentUser\My (Import-PfxCertificate returns cert object(s))
    Write-Host "Importing PFX into Cert:\CurrentUser\My..." -ForegroundColor Cyan
    $imported = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword -Exportable -ErrorAction Stop       
    if (-not $imported) { throw "Failed to import PFX into CurrentUser store." }
    if ($imported -is [System.Array]) { $cert = $imported[0] } else { $cert = $imported }

    $thumb = $cert.Thumbprint
    Write-Host "Imported certificate thumbprint: $thumb" -ForegroundColor Green

    # Helper: add certificate to a store using X509Store API
    function Add-CertToStore {
        param(
            [Parameter(Mandatory=$true)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $CertObj,
            [Parameter(Mandatory=$true)] [string] $StoreLocationStr,
            [Parameter(Mandatory=$true)] [string] $StoreName
        )
        try {
            $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
            if ($StoreLocationStr -ieq 'LocalMachine') { $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine }        

            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $storeLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $exists = $store.Certificates | Where-Object { $_.Thumbprint -eq $CertObj.Thumbprint }
            if (-not $exists) {
                $store.Add($CertObj)
                Write-Host ("Added certificate to Cert:\{0}\{1}" -f $StoreLocationStr, $StoreName) -ForegroundColor Green
            } else {
                Write-Host ("Certificate already present in Cert:\{0}\{1}" -f $StoreLocationStr, $StoreName) -ForegroundColor Yellow
            }
            $store.Close()
        }
        catch {
            throw ("Failed to add certificate to Cert:{0}\{1}: {2}" -f $StoreLocationStr, $StoreName, $_.Exception.Message)
        }
    }

    # Trust the certificate for the current user by adding to TrustedPublisher and Trusted Root
    foreach ($dest in @('CurrentUser\TrustedPublisher','CurrentUser\Root')) {
        $parts = $dest -split '\\'
        Add-CertToStore -CertObj $cert -StoreLocationStr $parts[0] -StoreName $parts[1]
    }

    # Determine if running elevated
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        # If elevated, also add to LocalMachine stores
        foreach ($dest in @('LocalMachine\TrustedPublisher','LocalMachine\Root')) {
            $parts = $dest -split '\\'
            Add-CertToStore -CertObj $cert -StoreLocationStr $parts[0] -StoreName $parts[1]
        }
        Write-Host "Certificate trusted for current user and LocalMachine." -ForegroundColor Green
    }
    else {
        Write-Host "Not running as Administrator. If signing still fails, re-run this script elevated to install the cert into LocalMachine stores." -ForegroundColor Yellow
    }

}
catch {
    Write-Host "Certificate creation/import/trust failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

function Get-SignToolPath {
    try {
        $where = & where.exe signtool 2>$null
        if ($LASTEXITCODE -eq 0 -and $where) {
            foreach ($p in $where) { if (Test-Path $p) { return $p } }
        }
    } catch {}

    $candidates = @()
    $kits10 = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path $kits10) {
        $candidates += Get-ChildItem -Path $kits10 -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -ExpandProperty FullName
    }
    $kits81 = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\8.1\bin\x64\signtool.exe'
    if (Test-Path $kits81) { $candidates += $kits81 }

    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function Write-Summary($results) {
    Write-Host ""; Write-Host "Summary:" -ForegroundColor White
    foreach ($r in $results) {
        Write-Host ("{0}: {1} -> {2}" -f $r.Version, $r.File, $r.Status)
        if ($r.Detail) { Write-Verbose ($r.Detail | Out-String) }
    }
}

# Locate signtool
$signtool = Get-SignToolPath
if (-not $signtool) { Write-Error "signtool.exe was not found on this machine. Install the Windows 10/11 SDK or ensure signtool is in PATH."; exit 1 }

# Validate inputs
if (-not (Test-Path $PfxPath)) { Write-Error "PFX file not found: $PfxPath"; exit 1 }
if (-not (Test-Path $BaseDir)) { Write-Error "Base directory not found: $BaseDir"; exit 1 }

Write-Verbose "Using signtool: $signtool"
Write-Verbose "Timestamp server: $TimestampUrl"

$results = @()

foreach ($ver in $Versions) {
    $dllPath = Join-Path $BaseDir ("bin\{0}\{1}" -f $ver, $DllName)

    if (-not (Test-Path $dllPath)) {
        Write-Warning ("Missing DLL for {0}: {1}" -f $ver, $dllPath)
        $results += [pscustomobject]@{ Version=$ver; File=$dllPath; Status='Missing'; Detail='' }
        continue
    }

    try {
        Write-Host ("Signing {0} ..." -f $dllPath) -ForegroundColor Cyan
        $signOutput = & $signtool sign /f $PfxPath /p $PfxPassword /fd sha256 /tr $TimestampUrl /td sha256 $dllPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("Sign failed for {0}: {1}" -f $ver, $dllPath) -ForegroundColor Red
            $results += [pscustomobject]@{ Version=$ver; File=$dllPath; Status='SignFailed'; Detail=($signOutput | Out-String).Trim() }
            continue
        }

        $verifyOutput = & $signtool verify /pa /v $dllPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("Verify failed for {0}: {1}" -f $ver, $dllPath) -ForegroundColor Yellow
            $results += [pscustomobject]@{ Version=$ver; File=$dllPath; Status='VerifyFailed'; Detail=($verifyOutput | Out-String).Trim() }
            continue
        }

        Write-Host ("Signed OK: {0}" -f $dllPath) -ForegroundColor Green
        $results += [pscustomobject]@{ Version=$ver; File=$dllPath; Status='Signed'; Detail='' }
    }
    catch {
        $msg = $_.Exception.Message
        Write-Host ("Error signing {0}: {1}" -f $dllPath, $msg) -ForegroundColor Red
        $results += [pscustomobject]@{ Version=$ver; File=$dllPath; Status='Error'; Detail=$msg }
    }
}

Write-Summary -results $results

$failed = $results | Where-Object { $_.Status -ne 'Signed' }
if ($failed) {
    Write-Host "Some DLLs failed to sign or are missing. See summary above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "All DLLs signed successfully." -ForegroundColor Green
    exit 0
}
