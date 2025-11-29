#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Fuzzes ECC certificate length bytes and logs results
.DESCRIPTION
    This script systematically fuzzes length bytes in X.509 certificates,
    logs all mutations and errors, and tracks parser behavior
#>

param(
    [string]$InputCert,
    [string]$Thumbprint,
    [string]$SubjectPattern,
    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$StoreLocation = "CurrentUser",
    [string]$StoreName = "My",
    [string]$OutputDir = "fuzz-results",
    [int]$MaxIterations = 1000,
    [ValidateSet("Sequential", "Random", "Boundary", "All")]
    [string]$FuzzMode = "All",
    [switch]$GenerateNew,
    [string]$SubjectName = "CN=fuzz-target",
    [switch]$VerboseLogging
)

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $OutputDir ("fuzz_log_" + $timestamp + ".txt")
$summaryFile = Join-Path $OutputDir ("fuzz_summary_" + $timestamp + ".txt")
$crashDir = Join-Path $OutputDir "crashes"

if (-not (Test-Path $crashDir)) {
    New-Item -ItemType Directory -Path $crashDir | Out-Null
}

# Statistics tracking
$script:stats = @{
    TotalIterations = 0
    SuccessfulParses = 0
    FailedParses = 0
    Crashes = 0
    UniqueLengthOffsets = @{}
    ErrorTypes = @{}
    StartTime = Get-Date
}

function Write-FuzzLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[" + $timestamp + "] [" + $Level + "] " + $Message
    
    Add-Content -Path $logFile -Value $logEntry
    
    if ($VerboseLogging -or $Level -eq "ERROR" -or $Level -eq "CRASH") {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "CRASH" { "Magenta" }
            "SUCCESS" { "Green" }
            "WARN" { "Yellow" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Get-ASN1Length {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )
    
    if ($Offset.Value -ge $Bytes.Length) {
        return -1
    }
    
    $firstByte = $Bytes[$Offset.Value]
    $Offset.Value++
    
    if ($firstByte -lt 0x80) {
        return $firstByte
    }
    
    $numOctets = $firstByte -band 0x7F
    
    if ($numOctets -eq 0 -or $numOctets -gt 4) {
        return -1
    }
    
    $length = 0
    
    for ($i = 0; $i -lt $numOctets; $i++) {
        if ($Offset.Value -ge $Bytes.Length) {
            return -1
        }
        $length = ($length -shl 8) -bor $Bytes[$Offset.Value]
        $Offset.Value++
    }
    
    return $length
}

function Find-LengthBytes {
    param([byte[]]$Bytes)
    
    $lengthOffsets = [System.Collections.Generic.List[object]]::new()
    $offset = 0
    
    while ($offset -lt $Bytes.Length) {
        if ($offset -ge $Bytes.Length) { break }
        
        $tagOffset = $offset
        $tag = $Bytes[$offset]
        $offset++
        
        if ($offset -ge $Bytes.Length) { break }
        
        $lengthOffset = $offset
        $lengthByte = $Bytes[$offset]
        
        $lengthInfo = @{
            TagOffset = $tagOffset
            Tag = $tag
            LengthOffset = $lengthOffset
            LengthByte = $lengthByte
            IsLongForm = ($lengthByte -band 0x80) -ne 0
            NumOctets = if (($lengthByte -band 0x80) -ne 0) { $lengthByte -band 0x7F } else { 0 }
        }
        
        $offsetRef = [ref]$offset
        $length = Get-ASN1Length -Bytes $Bytes -Offset $offsetRef
        $offset = $offsetRef.Value
        
        if ($length -ge 0) {
            $lengthInfo.Length = $length
            $lengthInfo.ContentStart = $offset
            $lengthOffsets.Add($lengthInfo)
            
            # Skip to next tag
            $offset = $offset + $length
            if ($offset -gt $Bytes.Length) { break }
        }
        else {
            break
        }
    }
    
    return $lengthOffsets
}

function Test-CertificateParsing {
    param([byte[]]$CertBytes)
    
    $result = @{
        Success = $false
        Error = $null
        ErrorType = $null
        ParsedElements = 0
    }
    
    try {
        # Try to parse as X509 certificate
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)
        $result.Success = $true
        $result.ParsedElements++
        
        # Try to access properties
        try { $null = $cert.Subject; $result.ParsedElements++ } catch { }
        try { $null = $cert.Issuer; $result.ParsedElements++ } catch { }
        try { $null = $cert.Thumbprint; $result.ParsedElements++ } catch { }
        try { $null = $cert.NotBefore; $result.ParsedElements++ } catch { }
        try { $null = $cert.NotAfter; $result.ParsedElements++ } catch { }
        try { $null = $cert.PublicKey; $result.ParsedElements++ } catch { }
        
        $cert.Dispose()
    }
    catch {
        $result.Success = $false
        $result.Error = $_.Exception.Message
        $result.ErrorType = $_.Exception.GetType().Name
    }
    
    return $result
}

function Invoke-FuzzIteration {
    param(
        [byte[]]$OriginalBytes,
        [hashtable]$LengthInfo,
        [byte]$NewValue,
        [int]$IterationNum
    )
    
    $script:stats.TotalIterations++
    
    # Clone the bytes
    $fuzzedBytes = [byte[]]::new($OriginalBytes.Length)
    [Array]::Copy($OriginalBytes, $fuzzedBytes, $OriginalBytes.Length)
    
    # Apply mutation
    $offset = $LengthInfo.LengthOffset
    $originalValue = $fuzzedBytes[$offset]
    $fuzzedBytes[$offset] = $NewValue
    
    # Log the mutation
    $mutationDesc = "ITERATION " + $IterationNum + ": OFFSET=" + $offset + " TAG=0x" + $LengthInfo.Tag.ToString("X2") + " ORIG=0x" + $originalValue.ToString("X2") + " NEW=0x" + $NewValue.ToString("X2")
    Write-FuzzLog -Message $mutationDesc -Level "INFO"
    
    # Track unique offsets
    if (-not $script:stats.UniqueLengthOffsets.ContainsKey($offset)) {
        $script:stats.UniqueLengthOffsets[$offset] = 0
    }
    $script:stats.UniqueLengthOffsets[$offset]++
    
    # Test parsing
    $parseResult = Test-CertificateParsing -CertBytes $fuzzedBytes
    
    if ($parseResult.Success) {
        $script:stats.SuccessfulParses++
        Write-FuzzLog -Message ("  RESULT: SUCCESS (PARSED " + $parseResult.ParsedElements + " ELEMENTS)") -Level "SUCCESS"
    }
    else {
        $script:stats.FailedParses++
        
        $errorType = if ($parseResult.ErrorType) { $parseResult.ErrorType } else { "UNKNOWN" }
        
        if (-not $script:stats.ErrorTypes.ContainsKey($errorType)) {
            $script:stats.ErrorTypes[$errorType] = 0
        }
        $script:stats.ErrorTypes[$errorType]++
        
        $errorMsg = if ($parseResult.Error) { $parseResult.Error } else { "UNKNOWN ERROR" }
        Write-FuzzLog -Message ("  RESULT: FAILED - " + $errorType + " - " + $errorMsg) -Level "ERROR"
        
        # Check for crash indicators
        if ($errorMsg -match "crash|violation|exception|corrupt" -or $errorType -match "AccessViolation|StackOverflow") {
            $script:stats.Crashes++
            
            # Save crash case
            $crashFile = Join-Path $crashDir ("crash_" + $IterationNum + "_offset" + $offset + ".cer")
            [System.IO.File]::WriteAllBytes($crashFile, $fuzzedBytes)
            
            Write-FuzzLog -Message ("  CRASH SAVED: " + $crashFile) -Level "CRASH"
        }
    }
    
    return $parseResult
}

function Get-FuzzValues {
    param(
        [string]$Mode,
        [byte]$OriginalValue
    )
    
    $values = [System.Collections.Generic.List[byte]]::new()
    
    switch ($Mode) {
        "Sequential" {
            # Test all possible byte values
            for ($i = 0; $i -le 255; $i++) {
                $values.Add([byte]$i)
            }
        }
        "Random" {
            # Random values
            for ($i = 0; $i -lt 50; $i++) {
                $values.Add([byte](Get-Random -Minimum 0 -Maximum 256))
            }
        }
        "Boundary" {
            # Boundary values for length encoding
            $values.Add([byte]0x00)       # Zero length
            $values.Add([byte]0x01)       # Minimal
            $values.Add([byte]0x7F)       # Max short form
            $values.Add([byte]0x80)       # Indefinite length
            $values.Add([byte]0x81)       # Long form, 1 octet
            $values.Add([byte]0x82)       # Long form, 2 octets
            $values.Add([byte]0x83)       # Long form, 3 octets
            $values.Add([byte]0x84)       # Long form, 4 octets
            $values.Add([byte]0xFF)       # Maximum value
            
            # Values around original
            if ($OriginalValue -gt 0) {
                $values.Add([byte]($OriginalValue - 1))
            }
            if ($OriginalValue -lt 255) {
                $values.Add([byte]($OriginalValue + 1))
            }
        }
        "All" {
            # Boundary values first
            $values.Add([byte]0x00)
            $values.Add([byte]0x01)
            $values.Add([byte]0x7F)
            $values.Add([byte]0x80)
            $values.Add([byte]0x81)
            $values.Add([byte]0x82)
            $values.Add([byte]0x83)
            $values.Add([byte]0x84)
            $values.Add([byte]0xFE)
            $values.Add([byte]0xFF)
            
            # Random sampling
            for ($i = 0; $i -lt 20; $i++) {
                $values.Add([byte](Get-Random -Minimum 0 -Maximum 256))
            }
        }
    }
    
    return $values
}

function Write-FuzzSummary {
    $duration = (Get-Date) - $script:stats.StartTime
    
    $summary = @"
================================================================================
                    CERTIFICATE FUZZING SUMMARY REPORT
================================================================================
EXECUTION TIME: $($duration.ToString("hh\:mm\:ss\.fff"))
TIMESTAMP: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

STATISTICS:
-----------
TOTAL ITERATIONS:        $($script:stats.TotalIterations)
SUCCESSFUL PARSES:       $($script:stats.SuccessfulParses) ($([math]::Round($script:stats.SuccessfulParses / $script:stats.TotalIterations * 100, 2))%)
FAILED PARSES:           $($script:stats.FailedParses) ($([math]::Round($script:stats.FailedParses / $script:stats.TotalIterations * 100, 2))%)
CRASHES DETECTED:        $($script:stats.Crashes)

UNIQUE LENGTH OFFSETS FUZZED:
-----------------------------
$($script:stats.UniqueLengthOffsets.Keys | Sort-Object | ForEach-Object { "OFFSET " + $_.ToString().PadLeft(4) + ": " + $script:stats.UniqueLengthOffsets[$_] + " ITERATIONS" } | Out-String)

ERROR TYPES ENCOUNTERED:
-----------------------
$($script:stats.ErrorTypes.Keys | Sort-Object | ForEach-Object { $_.PadRight(40) + ": " + $script:stats.ErrorTypes[$_] } | Out-String)

FILES GENERATED:
---------------
LOG FILE:        $logFile
SUMMARY FILE:    $summaryFile
CRASH DIRECTORY: $crashDir
CRASH FILES:     $(if (Test-Path $crashDir) { (Get-ChildItem $crashDir).Count } else { 0 })

================================================================================
"@
    
    Add-Content -Path $summaryFile -Value $summary
    Write-Host $summary -ForegroundColor Cyan
}

function Get-CertificateFromStore {
    param(
        [string]$Thumbprint,
        [string]$SubjectPattern,
        [string]$StoreLocation,
        [string]$StoreName
    )
    
    $storePath = "Cert:\" + $StoreLocation + "\" + $StoreName
    
    if ($Thumbprint) {
        $Thumbprint = $Thumbprint.ToUpper()
        $cert = Get-ChildItem -Path $storePath | Where-Object { $_.Thumbprint.ToUpper() -eq $Thumbprint }
        if (-not $cert) {
            Write-Host ("ERROR: CERTIFICATE WITH THUMBPRINT " + $Thumbprint + " NOT FOUND") -ForegroundColor Red
            return $null
        }
        return $cert
    }
    
    if ($SubjectPattern) {
        $certs = Get-ChildItem -Path $storePath | Where-Object { $_.Subject -like $SubjectPattern }
        if (-not $certs -or $certs.Count -eq 0) {
            Write-Host ("ERROR: NO CERTIFICATES FOUND MATCHING: " + $SubjectPattern) -ForegroundColor Red
            return $null
        }
        return $certs[0]
    }
    
    return $null
}

function New-FuzzTargetCertificate {
    param([string]$SubjectName)
    
    Write-Host "GENERATING NEW ECC CERTIFICATE FOR FUZZING..." -ForegroundColor Yellow
    
    $params = @{
        Subject = $SubjectName
        KeyAlgorithm = "ECDSA_nistP256"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays(1)
        KeyUsage = "DigitalSignature", "KeyAgreement"
        TextExtension = @(
            "2.5.29.37={text}1.3.6.1.5.5.7.3.1",
            "2.5.29.17={text}DNS=fuzz.test"
        )
    }
    
    $cert = New-SelfSignedCertificate @params
    $certBytes = $cert.RawData
    
    Write-Host ("CERTIFICATE GENERATED: " + $cert.Thumbprint) -ForegroundColor Green
    Write-Host ("SIZE: " + $certBytes.Length + " BYTES") -ForegroundColor Green
    
    # Clean up from store
    Remove-Item -Path ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -Force
    
    return $certBytes
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host ""
Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host "              ECC CERTIFICATE LENGTH BYTE FUZZER" -ForegroundColor Cyan
Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host ""

Write-FuzzLog -Message "FUZZING SESSION STARTED" -Level "INFO"
Write-FuzzLog -Message ("FUZZ MODE: " + $FuzzMode) -Level "INFO"
Write-FuzzLog -Message ("MAX ITERATIONS: " + $MaxIterations) -Level "INFO"
Write-FuzzLog -Message ("OUTPUT DIRECTORY: " + $OutputDir) -Level "INFO"

# Get the certificate bytes
$certBytes = $null

if ($GenerateNew) {
    $certBytes = New-FuzzTargetCertificate -SubjectName $SubjectName
}
elseif ($InputCert) {
    if (-not (Test-Path $InputCert)) {
        Write-Host ("ERROR: FILE NOT FOUND: " + $InputCert) -ForegroundColor Red
        exit 1
    }
    $certBytes = [System.IO.File]::ReadAllBytes($InputCert)
    Write-Host ("LOADED CERTIFICATE FROM FILE: " + $InputCert) -ForegroundColor Green
    Write-Host ("SIZE: " + $certBytes.Length + " BYTES") -ForegroundColor Green
}
elseif ($Thumbprint -or $SubjectPattern) {
    $cert = Get-CertificateFromStore -Thumbprint $Thumbprint -SubjectPattern $SubjectPattern -StoreLocation $StoreLocation -StoreName $StoreName
    if (-not $cert) {
        exit 1
    }
    $certBytes = $cert.RawData
    Write-Host ("LOADED CERTIFICATE FROM STORE: " + $cert.Subject) -ForegroundColor Green
    Write-Host ("SIZE: " + $certBytes.Length + " BYTES") -ForegroundColor Green
}
else {
    Write-Host "ERROR: MUST SPECIFY -INPUTCERT, -THUMBPRINT, -SUBJECTPATTERN, OR -GENERATENEW" -ForegroundColor Red
    exit 1
}

Write-FuzzLog -Message ("CERTIFICATE SIZE: " + $certBytes.Length + " BYTES") -Level "INFO"

# Find all length bytes in the certificate
Write-Host ""
Write-Host "ANALYZING CERTIFICATE STRUCTURE..." -ForegroundColor Yellow
$lengthInfos = Find-LengthBytes -Bytes $certBytes
Write-Host ("FOUND " + $lengthInfos.Count + " LENGTH FIELDS") -ForegroundColor Green

Write-FuzzLog -Message ("FOUND " + $lengthInfos.Count + " LENGTH FIELDS TO FUZZ") -Level "INFO"

foreach ($info in $lengthInfos) {
    $desc = "LENGTH FIELD: OFFSET=" + $info.LengthOffset + " TAG=0x" + $info.Tag.ToString("X2") + " VALUE=0x" + $info.LengthByte.ToString("X2") + " LENGTH=" + $info.Length
    Write-FuzzLog -Message $desc -Level "INFO"
}

# Start fuzzing
Write-Host ""
Write-Host "STARTING FUZZING CAMPAIGN..." -ForegroundColor Yellow
Write-Host ""

$iterationNum = 0

foreach ($lengthInfo in $lengthInfos) {
    if ($iterationNum -ge $MaxIterations) {
        Write-Host ("REACHED MAX ITERATIONS (" + $MaxIterations + ")") -ForegroundColor Yellow
        break
    }
    
    Write-Host ("FUZZING OFFSET " + $lengthInfo.LengthOffset + " (TAG 0x" + $lengthInfo.Tag.ToString("X2") + ")...") -ForegroundColor Cyan
    
    $fuzzValues = Get-FuzzValues -Mode $FuzzMode -OriginalValue $lengthInfo.LengthByte
    
    foreach ($value in $fuzzValues) {
        if ($iterationNum -ge $MaxIterations) {
            break
        }
        
        $iterationNum++
        Invoke-FuzzIteration -OriginalBytes $certBytes -LengthInfo $lengthInfo -NewValue $value -IterationNum $iterationNum
        
        # Progress indicator
        if ($iterationNum % 10 -eq 0) {
            Write-Host ("  PROGRESS: " + $iterationNum + " ITERATIONS COMPLETED") -ForegroundColor Gray
        }
    }
}

# Write summary
Write-Host ""
Write-Host "FUZZING CAMPAIGN COMPLETED" -ForegroundColor Green
Write-Host ""

Write-FuzzLog -Message "FUZZING SESSION COMPLETED" -Level "INFO"
Write-FuzzSummary

Write-Host ""
Write-Host "RESULTS SAVED TO: " + $OutputDir -ForegroundColor Cyan
Write-Host "  LOG FILE:     " + $logFile -ForegroundColor Cyan
Write-Host "  SUMMARY FILE: " + $summaryFile -ForegroundColor Cyan
Write-Host ""
