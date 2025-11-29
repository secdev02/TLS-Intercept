#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Generates ECC Certificates for TLS 1.3 and parses ASN.1 structure
.DESCRIPTION
    This script creates elliptic curve certificates suitable for TLS 1.3
    and provides detailed ASN.1 parsing showing bytes, offsets, and lengths
#>

param(
    [string]$CertPath = "ecc-cert.pfx",
    [string]$Password = "P@ssw0rd123!",
    [string]$SubjectName = "CN=localhost",
    [int]$ValidDays = 365,
    [switch]$ParseOnly,
    [string]$ParseFile,
    [string]$Thumbprint,
    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$StoreLocation = "CurrentUser",
    [string]$StoreName = "My",
    [int]$ModifyOffset = -1,
    [string]$ModifyValue,
    [switch]$ListCertificates
)

# ASN.1 Tag Types
$script:ASN1_TAGS = @{
    0x01 = "BOOLEAN"
    0x02 = "INTEGER"
    0x03 = "BIT STRING"
    0x04 = "OCTET STRING"
    0x05 = "NULL"
    0x06 = "OBJECT IDENTIFIER"
    0x0C = "UTF8String"
    0x13 = "PrintableString"
    0x16 = "IA5String"
    0x17 = "UTCTime"
    0x18 = "GeneralizedTime"
    0x30 = "SEQUENCE"
    0x31 = "SET"
    0xA0 = "CONTEXT [0]"
    0xA1 = "CONTEXT [1]"
    0xA2 = "CONTEXT [2]"
    0xA3 = "CONTEXT [3]"
}

# OID Lookup Table
$script:OID_LOOKUP = @{
    "1.2.840.10045.2.1" = "ecPublicKey"
    "1.2.840.10045.3.1.7" = "prime256v1 (secp256r1)"
    "1.3.132.0.34" = "secp384r1"
    "1.3.132.0.35" = "secp521r1"
    "1.2.840.10045.4.3.2" = "ecdsa-with-SHA256"
    "1.2.840.10045.4.3.3" = "ecdsa-with-SHA384"
    "1.2.840.10045.4.3.4" = "ecdsa-with-SHA512"
    "2.5.4.3" = "commonName"
    "2.5.4.6" = "countryName"
    "2.5.4.7" = "localityName"
    "2.5.4.8" = "stateOrProvinceName"
    "2.5.4.10" = "organizationName"
    "2.5.4.11" = "organizationalUnitName"
    "2.5.29.14" = "subjectKeyIdentifier"
    "2.5.29.15" = "keyUsage"
    "2.5.29.17" = "subjectAltName"
    "2.5.29.19" = "basicConstraints"
    "2.5.29.35" = "authorityKeyIdentifier"
    "2.5.29.37" = "extKeyUsage"
    "1.3.6.1.5.5.7.3.1" = "serverAuth"
    "1.3.6.1.5.5.7.3.2" = "clientAuth"
}

function Get-ASN1Length {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )
    
    $firstByte = $Bytes[$Offset.Value]
    $Offset.Value++
    
    if ($firstByte -lt 0x80) {
        return $firstByte
    }
    
    $numOctets = $firstByte -band 0x7F
    $length = 0
    
    for ($i = 0; $i -lt $numOctets; $i++) {
        $length = ($length -shl 8) -bor $Bytes[$Offset.Value]
        $Offset.Value++
    }
    
    return $length
}

function Get-OIDString {
    param([byte[]]$OidBytes)
    
    if ($OidBytes.Length -eq 0) { return "" }
    
    $result = [System.Collections.Generic.List[string]]::new()
    
    # First byte encodes first two nodes
    $firstByte = $OidBytes[0]
    $result.Add([string][Math]::Floor($firstByte / 40))
    $result.Add([string]($firstByte % 40))
    
    $value = 0
    for ($i = 1; $i -lt $OidBytes.Length; $i++) {
        $byte = $OidBytes[$i]
        $value = ($value -shl 7) -bor ($byte -band 0x7F)
        
        if (($byte -band 0x80) -eq 0) {
            $result.Add([string]$value)
            $value = 0
        }
    }
    
    return [string]::Join(".", $result)
}

function Get-CertificateFromStore {
    param(
        [string]$Thumbprint,
        [string]$StoreLocation,
        [string]$StoreName
    )
    
    $storePath = "Cert:\" + $StoreLocation + "\" + $StoreName
    
    if ($Thumbprint) {
        $cert = Get-ChildItem -Path $storePath | Where-Object { $_.Thumbprint -eq $Thumbprint }
        if (-not $cert) {
            Write-Error ("Certificate with thumbprint " + $Thumbprint + " not found in " + $storePath)
            return $null
        }
        return $cert
    }
    
    return $null
}

function Show-CertificateList {
    param(
        [string]$StoreLocation,
        [string]$StoreName
    )
    
    $storePath = "Cert:\" + $StoreLocation + "\" + $StoreName
    
    Write-Host ("=== Certificates in " + $storePath + " ===") -ForegroundColor Cyan
    Write-Host ""
    
    try {
        $certs = Get-ChildItem -Path $storePath -ErrorAction Stop
        
        if ($certs.Count -eq 0) {
            Write-Host "No certificates found in this store." -ForegroundColor Yellow
            return
        }
        
        foreach ($cert in $certs) {
            $keyAlg = $cert.PublicKey.Oid.FriendlyName
            $isECC = $keyAlg -like "*ECC*" -or $keyAlg -like "*ECDSA*"
            
            Write-Host ("Subject: " + $cert.Subject) -ForegroundColor White
            Write-Host ("  Thumbprint: " + $cert.Thumbprint) -ForegroundColor Gray
            Write-Host ("  Valid From: " + $cert.NotBefore) -ForegroundColor Gray
            Write-Host ("  Valid To:   " + $cert.NotAfter) -ForegroundColor Gray
            Write-Host ("  Algorithm:  " + $keyAlg) -ForegroundColor $(if ($isECC) { "Green" } else { "Gray" })
            Write-Host ("  Issuer:     " + $cert.Issuer) -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host ("Total: " + $certs.Count + " certificate(s)") -ForegroundColor Cyan
    }
    catch {
        Write-Error ("Failed to access store: " + $_.Exception.Message)
    }
}

function Export-CertificateBytes {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    return $Certificate.RawData
}

function Set-ByteAtOffset {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [string]$Value
    )
    
    if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) {
        Write-Error ("Offset " + $Offset + " is out of range (0-" + ($Bytes.Length - 1) + ")")
        return $Bytes
    }
    
    # Parse the value - support hex (0xAB) or decimal
    [byte]$newByte = 0
    if ($Value -match '^0x([0-9A-Fa-f]{1,2})$') {
        $newByte = [Convert]::ToByte($matches[1], 16)
    }
    elseif ($Value -match '^\d+$') {
        $newByte = [byte]$Value
    }
    else {
        Write-Error ("Invalid byte value: " + $Value + ". Use decimal (0-255) or hex (0x00-0xFF)")
        return $Bytes
    }
    
    $originalByte = $Bytes[$Offset]
    $Bytes[$Offset] = $newByte
    
    Write-Host ""
    Write-Host "=== Byte Modification ===" -ForegroundColor Yellow
    Write-Host ("Offset:        " + $Offset)
    Write-Host ("Original byte: 0x" + $originalByte.ToString("X2") + " (" + $originalByte + ")")
    Write-Host ("New byte:      0x" + $newByte.ToString("X2") + " (" + $newByte + ")")
    Write-Host ""
    Write-Host "WARNING: Modified certificate data - signature will be invalid!" -ForegroundColor Red
    Write-Host ""
    
    return $Bytes
}

function Format-HexDump {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [int]$Length,
        [int]$MaxDisplay = 32
    )
    
    $displayLength = [Math]::Min($Length, $MaxDisplay)
    $hex = [System.Collections.Generic.List[string]]::new()
    
    for ($i = 0; $i -lt $displayLength; $i++) {
        $hex.Add($Bytes[$Offset + $i].ToString("X2"))
    }
    
    $result = [string]::Join(" ", $hex)
    
    if ($Length -gt $MaxDisplay) {
        $result = $result + " ... (" + ([string]($Length - $MaxDisplay)) + " more bytes)"
    }
    
    return $result
}

function Parse-ASN1 {
    param(
        [byte[]]$Bytes,
        [int]$StartOffset = 0,
        [int]$MaxLength = -1,
        [int]$Indent = 0
    )
    
    if ($MaxLength -eq -1) {
        $MaxLength = $Bytes.Length - $StartOffset
    }
    
    $offset = $StartOffset
    $endOffset = $StartOffset + $MaxLength
    
    while ($offset -lt $endOffset -and $offset -lt $Bytes.Length) {
        $tag = $Bytes[$offset]
        $tagStart = $offset
        $offset++
        
        if ($offset -ge $Bytes.Length) { break }
        
        $lengthStart = $offset
        $lengthRef = [ref]$offset
        $length = Get-ASN1Length -Bytes $Bytes -Offset $lengthRef
        $contentStart = $offset
        
        # Build output line
        $indent_str = " " * ($Indent * 2)
        $tagName = $script:ASN1_TAGS[$tag]
        if (-not $tagName) {
            $tagName = "TAG[" + $tag.ToString("X2") + "]"
        }
        
        $offsetStr = "Offset: " + $tagStart.ToString().PadLeft(6)
        $lengthStr = "Length: " + $length.ToString().PadLeft(6)
        $headerStr = $indent_str + $offsetStr + " | " + $lengthStr + " | " + $tagName
        
        # Determine if this is a constructed type
        $isConstructed = ($tag -band 0x20) -ne 0
        
        # Handle specific types
        $valueStr = ""
        
        if ($tag -eq 0x06) {  # OBJECT IDENTIFIER
            if ($length -gt 0 -and ($contentStart + $length) -le $Bytes.Length) {
                $oidBytes = $Bytes[$contentStart..($contentStart + $length - 1)]
                $oidString = Get-OIDString -OidBytes $oidBytes
                $oidName = $script:OID_LOOKUP[$oidString]
                if ($oidName) {
                    $valueStr = " = " + $oidString + " (" + $oidName + ")"
                } else {
                    $valueStr = " = " + $oidString
                }
            }
            Write-Host $headerStr -NoNewline
            Write-Host $valueStr -ForegroundColor Cyan
            $hexDump = Format-HexDump -Bytes $Bytes -Offset $contentStart -Length $length
            Write-Host ($indent_str + "  Data: " + $hexDump) -ForegroundColor DarkGray
        }
        elseif ($tag -eq 0x02) {  # INTEGER
            Write-Host $headerStr -ForegroundColor Yellow
            $hexDump = Format-HexDump -Bytes $Bytes -Offset $contentStart -Length $length
            Write-Host ($indent_str + "  Data: " + $hexDump) -ForegroundColor DarkGray
        }
        elseif ($tag -eq 0x03) {  # BIT STRING
            Write-Host $headerStr -ForegroundColor Magenta
            $hexDump = Format-HexDump -Bytes $Bytes -Offset $contentStart -Length $length
            Write-Host ($indent_str + "  Data: " + $hexDump) -ForegroundColor DarkGray
        }
        elseif ($tag -eq 0x04) {  # OCTET STRING
            Write-Host $headerStr -ForegroundColor Blue
            $hexDump = Format-HexDump -Bytes $Bytes -Offset $contentStart -Length $length
            Write-Host ($indent_str + "  Data: " + $hexDump) -ForegroundColor DarkGray
        }
        elseif ($tag -eq 0x13 -or $tag -eq 0x0C -or $tag -eq 0x16) {  # PrintableString, UTF8String, IA5String
            if ($length -gt 0 -and ($contentStart + $length) -le $Bytes.Length) {
                $strBytes = $Bytes[$contentStart..($contentStart + $length - 1)]
                $strValue = [System.Text.Encoding]::UTF8.GetString($strBytes)
                $valueStr = " = '" + $strValue + "'"
            }
            Write-Host $headerStr -NoNewline
            Write-Host $valueStr -ForegroundColor Green
        }
        elseif ($tag -eq 0x17 -or $tag -eq 0x18) {  # UTCTime, GeneralizedTime
            if ($length -gt 0 -and ($contentStart + $length) -le $Bytes.Length) {
                $strBytes = $Bytes[$contentStart..($contentStart + $length - 1)]
                $strValue = [System.Text.Encoding]::ASCII.GetString($strBytes)
                $valueStr = " = " + $strValue
            }
            Write-Host $headerStr -NoNewline
            Write-Host $valueStr -ForegroundColor Cyan
        }
        elseif ($isConstructed -or $tag -eq 0x30 -or $tag -eq 0x31) {  # SEQUENCE or SET
            Write-Host $headerStr -ForegroundColor White
            if ($length -gt 0 -and ($contentStart + $length) -le $Bytes.Length) {
                Parse-ASN1 -Bytes $Bytes -StartOffset $contentStart -MaxLength $length -Indent ($Indent + 1)
            }
        }
        else {
            Write-Host $headerStr
            if ($length -gt 0 -and $length -le 64 -and ($contentStart + $length) -le $Bytes.Length) {
                $hexDump = Format-HexDump -Bytes $Bytes -Offset $contentStart -Length $length
                Write-Host ($indent_str + "  Data: " + $hexDump) -ForegroundColor DarkGray
            }
        }
        
        # Move to next tag
        $offset = $contentStart + $length
        
        if ($offset -gt $endOffset) { break }
    }
}

function New-ECCCertificate {
    param(
        [string]$SubjectName,
        [string]$OutputPath,
        [string]$Password,
        [int]$ValidDays
    )
    
    Write-Host "`n=== Generating ECC Certificate for TLS 1.3 ===" -ForegroundColor Green
    Write-Host ("Subject: " + $SubjectName)
    Write-Host ("Curve: NIST P-256 (secp256r1)")
    Write-Host ("Signature Algorithm: ECDSA with SHA-256")
    Write-Host ""
    
    # Create the certificate request
    $params = @{
        Subject = $SubjectName
        KeyAlgorithm = "ECDSA_nistP256"
        CertStoreLocation = "Cert:\CurrentUser\My"
        NotAfter = (Get-Date).AddDays($ValidDays)
        KeyUsage = "DigitalSignature", "KeyAgreement"
        TextExtension = @(
            "2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",  # Extended Key Usage: Server Auth, Client Auth
            "2.5.29.17={text}DNS=localhost&DNS=127.0.0.1"  # Subject Alternative Name
        )
    }
    
    $cert = New-SelfSignedCertificate @params
    
    Write-Host "Certificate created successfully!" -ForegroundColor Green
    Write-Host ("Thumbprint: " + $cert.Thumbprint)
    Write-Host ("Valid From: " + $cert.NotBefore)
    Write-Host ("Valid To: " + $cert.NotAfter)
    Write-Host ""
    
    # Export to PFX
    $securePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
    $pfxPath = Join-Path (Get-Location) $OutputPath
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword | Out-Null
    
    Write-Host ("Certificate exported to: " + $pfxPath) -ForegroundColor Green
    
    # Also export the public certificate for parsing
    $cerPath = $pfxPath -replace '\.pfx$', '.cer'
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    
    Write-Host ("Public certificate exported to: " + $cerPath) -ForegroundColor Green
    
    # Clean up from cert store
    Remove-Item -Path ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -Force
    
    return $cerPath
}

# Main execution
Write-Host "=== ECC Certificate Generator and ASN.1 Parser ===" -ForegroundColor Cyan
Write-Host ""

# Handle list certificates mode
if ($ListCertificates) {
    Show-CertificateList -StoreLocation $StoreLocation -StoreName $StoreName
    exit 0
}

# Determine source of certificate bytes
$certBytes = $null
$sourceDescription = ""

if ($ParseOnly -and $ParseFile) {
    # Parse existing file
    if (-not (Test-Path $ParseFile)) {
        Write-Error ("File not found: " + $ParseFile)
        exit 1
    }
    
    $sourceDescription = "File: " + $ParseFile
    $certBytes = [System.IO.File]::ReadAllBytes($ParseFile)
}
elseif ($Thumbprint) {
    # Read from certificate store
    Write-Host ("Reading certificate from store: Cert:\" + $StoreLocation + "\" + $StoreName) -ForegroundColor Yellow
    Write-Host ("Thumbprint: " + $Thumbprint) -ForegroundColor Yellow
    Write-Host ""
    
    $cert = Get-CertificateFromStore -Thumbprint $Thumbprint -StoreLocation $StoreLocation -StoreName $StoreName
    if (-not $cert) {
        Write-Host ""
        Write-Host "Tip: Use -ListCertificates to see available certificates" -ForegroundColor Cyan
        exit 1
    }
    
    Write-Host ("Found certificate: " + $cert.Subject) -ForegroundColor Green
    Write-Host ("  Algorithm: " + $cert.PublicKey.Oid.FriendlyName) -ForegroundColor Green
    Write-Host ("  Valid: " + $cert.NotBefore + " to " + $cert.NotAfter) -ForegroundColor Green
    Write-Host ""
    
    $sourceDescription = "Store: Cert:\" + $StoreLocation + "\" + $StoreName + " (" + $Thumbprint + ")"
    $certBytes = Export-CertificateBytes -Certificate $cert
}
else {
    # Generate new certificate
    $cerPath = New-ECCCertificate -SubjectName $SubjectName -OutputPath $CertPath -Password $Password -ValidDays $ValidDays
    
    $sourceDescription = "Generated: " + $cerPath
    $certBytes = [System.IO.File]::ReadAllBytes($cerPath)
}

# Apply byte modification if requested
if ($ModifyOffset -ge 0) {
    if (-not $ModifyValue) {
        Write-Error "ModifyValue parameter is required when ModifyOffset is specified"
        exit 1
    }
    
    $certBytes = Set-ByteAtOffset -Bytes $certBytes -Offset $ModifyOffset -Value $ModifyValue
}

# Parse the certificate
Write-Host ("=== Parsing Certificate ===" ) -ForegroundColor Cyan
Write-Host ("Source: " + $sourceDescription) -ForegroundColor Gray
Write-Host ("Total size: " + $certBytes.Length + " bytes") -ForegroundColor Gray
Write-Host ""
Write-Host "=== ASN.1 Structure ===" -ForegroundColor Cyan
Write-Host ""

Parse-ASN1 -Bytes $certBytes

Write-Host ""
Write-Host "=== Complete ===" -ForegroundColor Green
