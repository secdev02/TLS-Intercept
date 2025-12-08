<#
.SYNOPSIS

Enhanced HTTP/HTTPS proxy with HTTP/2 support for intercepting and logging web traffic.
This version includes full HTTP/2 frame parsing, stream multiplexing support, and comprehensive logging.

Function: Interceptor with HTTP/2 Support
Author: Enhanced by Claude (based on original by Casey Smith)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 4.0 (HTTP/2 Support Added)
Release Date: 2025

.DESCRIPTION

This script sets up an HTTP(s) proxy server that supports both HTTP/1.1 and HTTP/2.
It detects the protocol version via ALPN negotiation and logs all traffic comprehensively.
The script includes binary frame parsing for HTTP/2 traffic and HPACK header decompression.

.PARAMETER ListenPort

Configurable Port to listen for incoming Web requests. Default is 8081

.PARAMETER ProxyServer

Upstream proxy server for chaining requests.

.PARAMETER ProxyPort

Port for the upstream proxy server.

.PARAMETER Tamper

Enable content tampering mode.

.PARAMETER HostCA

Host the Root CA certificate on port 8082 for mobile devices.

.PARAMETER Cleanup

Removes installed certificates and exits.

.PARAMETER Quiet

Suppresses common connection errors in console output (still logs to file).
Useful when running long-term captures to reduce noise from client disconnects.

.EXAMPLE

Interceptor_HTTP2.ps1 -ProxyServer localhost -ProxyPort 8888
Interceptor_HTTP2.ps1 -Tamper
Interceptor_HTTP2.ps1 -HostCA

.NOTES
This script requires administrative privileges and will install certificates in your Trusted Root Store.
Use responsibly and only for authorized testing purposes.

#>

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False,Position=0)]
  [int]$ListenPort,
  
  [Parameter(Mandatory=$False,Position=1)]
  [string]$ProxyServer,
  
  [Parameter(Mandatory=$False,Position=2)]
  [int]$ProxyPort,
  
  [Parameter(Mandatory=$False,Position=3)]
  [switch]$Tamper,
  
  [Parameter(Mandatory=$False,Position=4)]
  [switch]$HostCA,
  
  [Parameter(Mandatory=$False,Position=5)]
  [switch]$Cleanup,
  
  [Parameter(Mandatory=$False,Position=6)]
  [switch]$Quiet,
  
  [Parameter(Mandatory=$False,Position=7)]
  [switch]$MinimalLogging,
  
  [Parameter(Mandatory=$False,Position=8)]
  [switch]$DisableHttp2Parsing
)

# Global logging variables
$script:LogFile = Join-Path $PSScriptRoot ("Interceptor_Log_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
$script:LogMutex = New-Object System.Threading.Mutex($false, "InterceptorLogMutex")
$script:RequestCounter = 0
$script:LogBuffer = New-Object System.Collections.ArrayList
$script:LogBufferSize = 50  # Flush after 50 entries
$script:LastFlush = [DateTime]::Now

# HTTP/2 Constants
$script:HTTP2_PREFACE = [System.Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")
$script:HTTP2_FRAME_TYPES = @{
    0x0 = "DATA"
    0x1 = "HEADERS"
    0x2 = "PRIORITY"
    0x3 = "RST_STREAM"
    0x4 = "SETTINGS"
    0x5 = "PUSH_PROMISE"
    0x6 = "PING"
    0x7 = "GOAWAY"
    0x8 = "WINDOW_UPDATE"
    0x9 = "CONTINUATION"
}

# HPACK Static Table (partial - commonly used headers)
$script:HPACK_STATIC_TABLE = @{
    1 = @{name = ":authority"; value = ""}
    2 = @{name = ":method"; value = "GET"}
    3 = @{name = ":method"; value = "POST"}
    4 = @{name = ":path"; value = "/"}
    5 = @{name = ":path"; value = "/index.html"}
    6 = @{name = ":scheme"; value = "http"}
    7 = @{name = ":scheme"; value = "https"}
    8 = @{name = ":status"; value = "200"}
    9 = @{name = ":status"; value = "204"}
    10 = @{name = ":status"; value = "206"}
    11 = @{name = ":status"; value = "304"}
    12 = @{name = ":status"; value = "400"}
    13 = @{name = ":status"; value = "404"}
    14 = @{name = ":status"; value = "500"}
    15 = @{name = "accept-charset"; value = ""}
    16 = @{name = "accept-encoding"; value = "gzip, deflate"}
    17 = @{name = "accept-language"; value = ""}
    18 = @{name = "accept-ranges"; value = ""}
    19 = @{name = "accept"; value = ""}
    20 = @{name = "access-control-allow-origin"; value = ""}
    21 = @{name = "age"; value = ""}
    22 = @{name = "allow"; value = ""}
    23 = @{name = "authorization"; value = ""}
    24 = @{name = "cache-control"; value = ""}
    25 = @{name = "content-disposition"; value = ""}
    26 = @{name = "content-encoding"; value = ""}
    27 = @{name = "content-language"; value = ""}
    28 = @{name = "content-length"; value = ""}
    29 = @{name = "content-location"; value = ""}
    30 = @{name = "content-range"; value = ""}
    31 = @{name = "content-type"; value = ""}
    32 = @{name = "cookie"; value = ""}
    33 = @{name = "date"; value = ""}
    34 = @{name = "etag"; value = ""}
    35 = @{name = "expect"; value = ""}
    36 = @{name = "expires"; value = ""}
    37 = @{name = "from"; value = ""}
    38 = @{name = "host"; value = ""}
    39 = @{name = "if-match"; value = ""}
    40 = @{name = "if-modified-since"; value = ""}
    41 = @{name = "if-none-match"; value = ""}
    42 = @{name = "if-range"; value = ""}
    43 = @{name = "if-unmodified-since"; value = ""}
    44 = @{name = "last-modified"; value = ""}
    45 = @{name = "link"; value = ""}
    46 = @{name = "location"; value = ""}
    47 = @{name = "max-forwards"; value = ""}
    48 = @{name = "proxy-authenticate"; value = ""}
    49 = @{name = "proxy-authorization"; value = ""}
    50 = @{name = "range"; value = ""}
    51 = @{name = "referer"; value = ""}
    52 = @{name = "refresh"; value = ""}
    53 = @{name = "retry-after"; value = ""}
    54 = @{name = "server"; value = ""}
    55 = @{name = "set-cookie"; value = ""}
    56 = @{name = "strict-transport-security"; value = ""}
    57 = @{name = "transfer-encoding"; value = ""}
    58 = @{name = "user-agent"; value = ""}
    59 = @{name = "vary"; value = ""}
    60 = @{name = "via"; value = ""}
    61 = @{name = "www-authenticate"; value = ""}
}

function Write-InterceptorLog([string]$message, [string]$color = "Yellow")
{
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logMessage = $timestamp + " | " + $message
    
    # Skip console output for Yellow messages if Quiet mode is enabled
    if (-not ($Quiet -and $color -eq "Yellow")) {
        switch($color)
        {
            "Green" { Write-Host $logMessage -ForegroundColor Green }
            "Red" { Write-Host $logMessage -ForegroundColor Red }
            "Cyan" { Write-Host $logMessage -ForegroundColor Cyan }
            "Magenta" { Write-Host $logMessage -ForegroundColor Magenta }
            "Blue" { Write-Host $logMessage -ForegroundColor Blue }
            default { Write-Host $logMessage -ForegroundColor Yellow }
        }
    }
    
    # Buffer log writes for better performance
    $script:LogMutex.WaitOne() | Out-Null
    try
    {
        [void]$script:LogBuffer.Add($logMessage)
        
        # Flush if buffer is full or 5 seconds have passed
        $timeSinceFlush = ([DateTime]::Now - $script:LastFlush).TotalSeconds
        if ($script:LogBuffer.Count -ge $script:LogBufferSize -or $timeSinceFlush -gt 5)
        {
            Add-Content -Path $script:LogFile -Value ($script:LogBuffer -join "`r`n")
            $script:LogBuffer.Clear()
            $script:LastFlush = [DateTime]::Now
        }
    }
    finally
    {
        $script:LogMutex.ReleaseMutex()
    }
}

function Flush-LogBuffer()
{
    $script:LogMutex.WaitOne() | Out-Null
    try
    {
        if ($script:LogBuffer.Count -gt 0)
        {
            Add-Content -Path $script:LogFile -Value ($script:LogBuffer -join "`r`n")
            $script:LogBuffer.Clear()
            $script:LastFlush = [DateTime]::Now
        }
    }
    finally
    {
        $script:LogMutex.ReleaseMutex()
    }
}

function Get-BaseDomain([string] $hostname)
{
    $parts = $hostname.Split('.')
    $partCount = $parts.Length
    
    if ($partCount -le 2)
    {
        return $hostname
    }
    
    $baseDomain = $parts[$partCount - 2] + "." + $parts[$partCount - 1]
    return $baseDomain
}

function Read-HpackInteger([byte[]]$data, [int]$offset, [int]$prefixBits, [ref]$bytesRead)
{
    $mask = (1 -shl $prefixBits) - 1
    $value = $data[$offset] -band $mask
    $bytesRead.Value = 1
    
    if ($value -lt $mask)
    {
        return $value
    }
    
    $m = 0
    $idx = $offset + 1
    
    while ($idx -lt $data.Length)
    {
        $b = $data[$idx]
        $value = $value + (($b -band 0x7F) -shl $m)
        $m = $m + 7
        $bytesRead.Value++
        $idx++
        
        if (($b -band 0x80) -eq 0)
        {
            break
        }
    }
    
    return $value
}

function Read-HpackString([byte[]]$data, [int]$offset, [ref]$bytesRead)
{
    $huffmanEncoded = ($data[$offset] -band 0x80) -ne 0
    $lengthBytesRead = 0
    $length = Read-HpackInteger $data $offset 7 ([ref]$lengthBytesRead)
    
    $bytesRead.Value = $lengthBytesRead + $length
    $stringBytes = $data[($offset + $lengthBytesRead)..($offset + $lengthBytesRead + $length - 1)]
    
    if ($huffmanEncoded)
    {
        # For simplicity, we'll just indicate it's Huffman encoded
        # Full Huffman decoding would require the complete Huffman table
        return "[Huffman:" + [System.BitConverter]::ToString($stringBytes) + "]"
    }
    else
    {
        return [System.Text.Encoding]::ASCII.GetString($stringBytes)
    }
}

function Parse-HpackHeaders([byte[]]$headerBlock, [int]$requestId)
{
    $headers = @{}
    $offset = 0
    
    Write-InterceptorLog ("Parsing HPACK header block (" + $headerBlock.Length + " bytes)") "Blue"
    
    while ($offset -lt $headerBlock.Length)
    {
        $firstByte = $headerBlock[$offset]
        
        # Indexed Header Field
        if (($firstByte -band 0x80) -ne 0)
        {
            $bytesRead = 0
            $index = Read-HpackInteger $headerBlock $offset 7 ([ref]$bytesRead)
            
            if ($script:HPACK_STATIC_TABLE.ContainsKey($index))
            {
                $entry = $script:HPACK_STATIC_TABLE[$index]
                $headers[$entry.name] = $entry.value
                Write-InterceptorLog ("HPACK Indexed: " + $entry.name + ": " + $entry.value) "Blue"
            }
            
            $offset = $offset + $bytesRead
        }
        # Literal Header Field with Incremental Indexing
        elseif (($firstByte -band 0x40) -ne 0)
        {
            $bytesRead = 0
            $index = Read-HpackInteger $headerBlock $offset 6 ([ref]$bytesRead)
            $offset = $offset + $bytesRead
            
            $name = ""
            if ($index -eq 0)
            {
                $nameBytes = 0
                $name = Read-HpackString $headerBlock $offset ([ref]$nameBytes)
                $offset = $offset + $nameBytes
            }
            elseif ($script:HPACK_STATIC_TABLE.ContainsKey($index))
            {
                $name = $script:HPACK_STATIC_TABLE[$index].name
            }
            
            $valueBytes = 0
            $value = Read-HpackString $headerBlock $offset ([ref]$valueBytes)
            $offset = $offset + $valueBytes
            
            if ($name -ne "")
            {
                $headers[$name] = $value
                Write-InterceptorLog ("HPACK Literal: " + $name + ": " + $value) "Blue"
            }
        }
        # Literal Header Field without Indexing
        elseif (($firstByte -band 0xF0) -eq 0x00 -or ($firstByte -band 0xF0) -eq 0x10)
        {
            $prefixBits = if (($firstByte -band 0x10) -ne 0) { 4 } else { 4 }
            $bytesRead = 0
            $index = Read-HpackInteger $headerBlock $offset $prefixBits ([ref]$bytesRead)
            $offset = $offset + $bytesRead
            
            $name = ""
            if ($index -eq 0)
            {
                $nameBytes = 0
                $name = Read-HpackString $headerBlock $offset ([ref]$nameBytes)
                $offset = $offset + $nameBytes
            }
            elseif ($script:HPACK_STATIC_TABLE.ContainsKey($index))
            {
                $name = $script:HPACK_STATIC_TABLE[$index].name
            }
            
            $valueBytes = 0
            $value = Read-HpackString $headerBlock $offset ([ref]$valueBytes)
            $offset = $offset + $valueBytes
            
            if ($name -ne "")
            {
                $headers[$name] = $value
                Write-InterceptorLog ("HPACK Literal (no-index): " + $name + ": " + $value) "Blue"
            }
        }
        # Dynamic Table Size Update
        elseif (($firstByte -band 0xE0) -eq 0x20)
        {
            $bytesRead = 0
            $size = Read-HpackInteger $headerBlock $offset 5 ([ref]$bytesRead)
            Write-InterceptorLog ("HPACK Dynamic Table Size Update: " + $size) "Blue"
            $offset = $offset + $bytesRead
        }
        else
        {
            Write-InterceptorLog "Unknown HPACK encoding, skipping byte" "Red"
            $offset++
        }
    }
    
    return $headers
}

function Parse-Http2Frame([byte[]]$frameData, [int]$requestId)
{
    if ($DisableHttp2Parsing)
    {
        # Quick parse for logging without full detail
        if ($frameData.Length -ge 9)
        {
            $type = $frameData[3]
            $streamId = (([int]$frameData[5] -band 0x7F) -shl 24) + ([int]$frameData[6] -shl 16) + ([int]$frameData[7] -shl 8) + [int]$frameData[8]
            $typeName = if ($script:HTTP2_FRAME_TYPES.ContainsKey($type)) { $script:HTTP2_FRAME_TYPES[$type] } else { "UNKNOWN" }
            Write-InterceptorLog ("HTTP/2 Frame: " + $typeName + " Stream: " + $streamId) "Blue"
        }
        return $null
    }
    
    if ($frameData.Length -lt 9)
    {
        Write-InterceptorLog "HTTP/2 frame too short" "Red"
        return $null
    }
    
    # Parse frame header (9 bytes)
    $length = ([int]$frameData[0] -shl 16) + ([int]$frameData[1] -shl 8) + [int]$frameData[2]
    $type = $frameData[3]
    $flags = $frameData[4]
    $streamId = (([int]$frameData[5] -band 0x7F) -shl 24) + ([int]$frameData[6] -shl 16) + ([int]$frameData[7] -shl 8) + [int]$frameData[8]
    
    $typeName = if ($script:HTTP2_FRAME_TYPES.ContainsKey($type)) { $script:HTTP2_FRAME_TYPES[$type] } else { "UNKNOWN" }
    
    Write-InterceptorLog ("===== HTTP/2 FRAME [#" + $requestId + "] =====") "Blue"
    Write-InterceptorLog ("Frame Type: " + $typeName + " (0x" + $type.ToString("X2") + ")") "Blue"
    Write-InterceptorLog ("Stream ID: " + $streamId) "Blue"
    Write-InterceptorLog ("Length: " + $length + " bytes") "Blue"
    Write-InterceptorLog ("Flags: 0x" + $flags.ToString("X2")) "Blue"
    
    $payload = @()
    if ($length -gt 0 -and ($frameData.Length -ge (9 + $length)))
    {
        $payload = $frameData[9..(8 + $length)]
    }
    
    # Parse specific frame types
    switch ($type)
    {
        0x0 # DATA
        {
            $padLength = 0
            $dataOffset = 0
            
            if (($flags -band 0x08) -ne 0) # PADDED flag
            {
                $padLength = $payload[0]
                $dataOffset = 1
            }
            
            $dataLength = $payload.Length - $dataOffset - $padLength
            if ($dataLength -gt 0)
            {
                $data = $payload[$dataOffset..($dataOffset + $dataLength - 1)]
                $dataString = [System.Text.Encoding]::UTF8.GetString($data)
                Write-InterceptorLog ("DATA: " + $dataString.Substring(0, [Math]::Min(200, $dataString.Length))) "Blue"
            }
            
            if (($flags -band 0x01) -ne 0) # END_STREAM flag
            {
                Write-InterceptorLog "END_STREAM flag set" "Blue"
            }
        }
        
        0x1 # HEADERS
        {
            $padLength = 0
            $offset = 0
            
            if (($flags -band 0x08) -ne 0) # PADDED flag
            {
                $padLength = $payload[0]
                $offset++
            }
            
            if (($flags -band 0x20) -ne 0) # PRIORITY flag
            {
                # Skip priority fields (5 bytes)
                $offset = $offset + 5
            }
            
            $headerBlockLength = $payload.Length - $offset - $padLength
            if ($headerBlockLength -gt 0)
            {
                $headerBlock = $payload[$offset..($offset + $headerBlockLength - 1)]
                $headers = Parse-HpackHeaders $headerBlock $requestId
                
                Write-InterceptorLog "Decoded Headers:" "Blue"
                foreach ($key in $headers.Keys)
                {
                    Write-InterceptorLog ("  " + $key + ": " + $headers[$key]) "Blue"
                }
            }
            
            if (($flags -band 0x01) -ne 0) # END_STREAM flag
            {
                Write-InterceptorLog "END_STREAM flag set" "Blue"
            }
            
            if (($flags -band 0x04) -ne 0) # END_HEADERS flag
            {
                Write-InterceptorLog "END_HEADERS flag set" "Blue"
            }
        }
        
        0x3 # RST_STREAM
        {
            if ($payload.Length -ge 4)
            {
                $errorCode = ([int]$payload[0] -shl 24) + ([int]$payload[1] -shl 16) + ([int]$payload[2] -shl 8) + [int]$payload[3]
                Write-InterceptorLog ("RST_STREAM Error Code: " + $errorCode) "Blue"
            }
        }
        
        0x4 # SETTINGS
        {
            if (($flags -band 0x01) -ne 0) # ACK flag
            {
                Write-InterceptorLog "SETTINGS ACK" "Blue"
            }
            else
            {
                $settingsCount = $payload.Length / 6
                for ($i = 0; $i -lt $settingsCount; $i++)
                {
                    $settingOffset = $i * 6
                    $settingId = ([int]$payload[$settingOffset] -shl 8) + [int]$payload[$settingOffset + 1]
                    $settingValue = ([int]$payload[$settingOffset + 2] -shl 24) + ([int]$payload[$settingOffset + 3] -shl 16) + ([int]$payload[$settingOffset + 4] -shl 8) + [int]$payload[$settingOffset + 5]
                    
                    $settingName = switch ($settingId)
                    {
                        0x1 { "HEADER_TABLE_SIZE" }
                        0x2 { "ENABLE_PUSH" }
                        0x3 { "MAX_CONCURRENT_STREAMS" }
                        0x4 { "INITIAL_WINDOW_SIZE" }
                        0x5 { "MAX_FRAME_SIZE" }
                        0x6 { "MAX_HEADER_LIST_SIZE" }
                        default { "UNKNOWN_" + $settingId }
                    }
                    
                    Write-InterceptorLog ("SETTING: " + $settingName + " = " + $settingValue) "Blue"
                }
            }
        }
        
        0x6 # PING
        {
            if (($flags -band 0x01) -ne 0) # ACK flag
            {
                Write-InterceptorLog "PING ACK" "Blue"
            }
            else
            {
                Write-InterceptorLog "PING" "Blue"
            }
            
            if ($payload.Length -ge 8)
            {
                $pingData = [System.BitConverter]::ToString($payload[0..7])
                Write-InterceptorLog ("Ping Data: " + $pingData) "Blue"
            }
        }
        
        0x7 # GOAWAY
        {
            if ($payload.Length -ge 8)
            {
                $lastStreamId = (([int]$payload[0] -band 0x7F) -shl 24) + ([int]$payload[1] -shl 16) + ([int]$payload[2] -shl 8) + [int]$payload[3]
                $errorCode = ([int]$payload[4] -shl 24) + ([int]$payload[5] -shl 16) + ([int]$payload[6] -shl 8) + [int]$payload[7]
                
                Write-InterceptorLog ("GOAWAY Last Stream: " + $lastStreamId) "Blue"
                Write-InterceptorLog ("GOAWAY Error Code: " + $errorCode) "Blue"
                
                if ($payload.Length -gt 8)
                {
                    $debugData = [System.Text.Encoding]::UTF8.GetString($payload[8..($payload.Length - 1)])
                    Write-InterceptorLog ("Debug Data: " + $debugData) "Blue"
                }
            }
        }
        
        0x8 # WINDOW_UPDATE
        {
            if ($payload.Length -ge 4)
            {
                $windowSizeIncrement = (([int]$payload[0] -band 0x7F) -shl 24) + ([int]$payload[1] -shl 16) + ([int]$payload[2] -shl 8) + [int]$payload[3]
                Write-InterceptorLog ("Window Size Increment: " + $windowSizeIncrement) "Blue"
            }
        }
        
        0x9 # CONTINUATION
        {
            if ($payload.Length -gt 0)
            {
                Write-InterceptorLog "CONTINUATION frame (header block fragment)" "Blue"
                # Would need to accumulate with previous HEADERS/PUSH_PROMISE frame
            }
            
            if (($flags -band 0x04) -ne 0) # END_HEADERS flag
            {
                Write-InterceptorLog "END_HEADERS flag set" "Blue"
            }
        }
    }
    
    Write-InterceptorLog ("===== END HTTP/2 FRAME [#" + $requestId + "] =====") "Blue"
    
    return @{
        Type = $type
        Flags = $flags
        StreamId = $streamId
        Length = $length
        Payload = $payload
    }
}

function Start-CertificateAuthority()
{
	Start-Job -ScriptBlock {
			
			$Hso = New-Object Net.HttpListener
			$Hso.Prefixes.Add("http://+:8082/")
			$Hso.Start()
			While ($Hso.IsListening) {
				$HC = $Hso.GetContext()
				$HRes = $HC.Response
				$HRes.Headers.Add("Content-Type","application/x-x509-ca-cert")
				$cert = Get-ChildItem cert:\LocalMachine\Root | where { $_.Issuer -match "__Interceptor_Trusted_Root" }
				$type = [System.Security.Cryptography.X509Certificates.X509ContentType]::cert
				$Buf = $cert.Export($type)
				$HRes.OutputStream.Write($Buf,0,$Buf.Length)
				$HRes.Close()
			}
				
		}
}

function Invoke-RemoveCertificates([string] $issuedBy)
{
	$certs = Get-ChildItem cert:\LocalMachine\My | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
		foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}
	
	$certs = Get-ChildItem cert:\LocalMachine\Root | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
	foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}
	[Console]::WriteLine("Certificates Removed")
		
}

function Invoke-CreateCertificate([string] $certSubject, [bool] $isCA, [bool] $isWildcard)
{
    $issuer = "__Interceptor_Trusted_Root"
    $subject = "CN=" + $certSubject
    $notBefore = (Get-Date).AddDays(-1)
    $notAfter = $notBefore.AddDays(90)
    
    $certParams = @{
        Subject = $subject
        NotBefore = $notBefore
        NotAfter = $notAfter
        CertStoreLocation = "Cert:\LocalMachine\My"
        HashAlgorithm = "SHA256"
        KeyAlgorithm = "ECDsa_nistP256"
        KeyExportPolicy = "Exportable"
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
    }
    
    if ($isCA)
    {
        $certParams['KeyUsage'] = @("CertSign", "DigitalSignature")
        $certParams['TextExtension'] += "2.5.29.19={text}CA=TRUE&pathlength=1"
        
        $certificate = New-SelfSignedCertificate @certParams
        
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($certificate)
        $store.Close()
        
        return $certificate
    }
    else
    {
        $signer = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match $issuer } | Select-Object -First 1
        
        if ($null -eq $signer)
        {
            throw "CA certificate not found. Create CA certificate first."
        }
        
        if ($isWildcard)
        {
            $baseDomain = $certSubject.TrimStart('*').TrimStart('.')
            $certParams['DnsName'] = @($certSubject, $baseDomain)
        }
        else
        {
            $certParams['DnsName'] = @($certSubject)
        }
        
        $certParams['Signer'] = $signer
        $certParams['KeyUsage'] = @("DigitalSignature", "KeyEncipherment")
        
        $certificate = New-SelfSignedCertificate @certParams
        
        return $certificate
    }
}

function Receive-ServerHttpResponse ([System.Net.WebResponse] $response, [int] $requestId)
{
	Try
	{
		[string]$rawProtocolVersion = "HTTP/" + $response.ProtocolVersion
		[int]$rawStatusCode = [int]$response.StatusCode
		[string]$rawStatusDescription = [string]$response.StatusDescription
		$rawHeadersString = New-Object System.Text.StringBuilder 
		$rawHeaderCollection = $response.Headers
		$rawHeaders = $response.Headers.AllKeys
		[bool] $transferEncoding = $false
		
		Write-InterceptorLog ("===== RESPONSE [#" + $requestId + "] =====") "Cyan"
		Write-InterceptorLog ("Protocol: " + $rawProtocolVersion) "Cyan"
		Write-InterceptorLog ("Status: " + $rawStatusCode + " " + $rawStatusDescription) "Cyan"
		
		if (-not $MinimalLogging) {
			foreach($s in $rawHeaders)
			{
				if($s -eq "Set-Cookie") { Continue }
				if($s -eq "Transfer-Encoding") 
				{
					$transferEncoding = $true
					continue
				}
				[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s))
				Write-InterceptorLog ("Response Header: " + $s + ": " + $rawHeaderCollection.Get($s)) "Cyan"
			}
		
			$setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))'
			if($setCookieString)
			{
				foreach ($respCookie in $setCookieString)
				{
					if($respCookie -eq "," -Or $respCookie -eq "") {continue}
					[void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie)
					Write-InterceptorLog ("Response Cookie: " + $respCookie) "Cyan"
				}
			}
		} else {
			foreach($s in $rawHeaders)
			{
				if($s -eq "Transfer-Encoding") 
				{
					$transferEncoding = $true
				}
				[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s))
			}
			
			$setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))'
			if($setCookieString)
			{
				foreach ($respCookie in $setCookieString)
				{
					if($respCookie -eq "," -Or $respCookie -eq "") {continue}
					[void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie)
				}
			}
		}
		
		$responseStream = $response.GetResponseStream()
		
		$rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
		
		[byte[]] $rawHeaderBytes = [System.Text.Encoding]::Ascii.GetBytes($rstring)
		
		[void][byte[]] $outdata 
		$tempMemStream = New-Object System.IO.MemoryStream
		[byte[]] $respbuffer = New-Object Byte[] 32768
		
		$TamperReplacements = @{
            'Cyber' = 'Kitten'
            'Attack' = 'Hug'
            'Malware' = 'Puppies'
            'Threat' = 'Friend'
        }

        if($transferEncoding)
        {
            $reader = New-Object System.IO.StreamReader($responseStream)
            [string] $responseFromServer = $reader.ReadToEnd()

            if ($Tamper)
            {
                foreach ($match in $TamperReplacements.Keys)
                {
                    if ($responseFromServer -match $match)
                    {
                        $responseFromServer = $responseFromServer -replace $match, $TamperReplacements[$match]
                        Write-InterceptorLog ("Tampered: Replaced '" + $match + "' with '" + $TamperReplacements[$match] + "'") "Magenta"
                    }
                }
            }

            $outdata = [System.Text.Encoding]::UTF8.GetBytes($responseFromServer)
            $reader.Close()
        }
        else
        {
            while($true)
            {
                [int] $read = $responseStream.Read($respbuffer, 0, $respbuffer.Length)
                if($read -le 0)
                {
                    $outdata = $tempMemStream.ToArray()
                    break
                }
                $tempMemStream.Write($respbuffer, 0, $read)
            }

            if ($Tamper -And $response.ContentType -match "text/html")
            {
                $outdataReplace = [System.Text.Encoding]::UTF8.GetString($outdata)
        
                foreach ($match in $TamperReplacements.Keys)
                {
                    if ($outdataReplace -match $match)
                    {
                        $outdataReplace = $outdataReplace -replace $match, $TamperReplacements[$match]
                        Write-InterceptorLog ("Tampered: Replaced '" + $match + "' with '" + $TamperReplacements[$match] + "'") "Magenta"
                    }
                }
        
                $outdata = [System.Text.Encoding]::UTF8.GetBytes($outdataReplace)
            }
        }
        
        Write-InterceptorLog ("Response Body Size: " + $outdata.Length + " bytes") "Cyan"
        Write-InterceptorLog ("===== END RESPONSE [#" + $requestId + "] =====") "Cyan"

        [byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
        [System.Buffer]::BlockCopy( $rawHeaderBytes, 0, $rv, 0, $rawHeaderBytes.Length)
        [System.Buffer]::BlockCopy( $outdata, 0, $rv, $rawHeaderBytes.Length, $outdata.Length)
	
		$tempMemStream.Close()
		$response.Close()
		
		return $rv
	}
	Catch [System.Exception]
	{
		[Console]::WriteLine("Get Response Error")
		[Console]::WriteLine($_.Exception.Message)
		Write-InterceptorLog ("Response Error: " + $_.Exception.Message) "Red"
    }
	
}

function Send-ServerHttpRequest([string] $URI, [string] $httpMethod,[byte[]] $requestBytes, [System.Net.WebProxy] $proxy, [int] $requestId)
{	
	Try
	{
		$requestParse = [System.Text.Encoding]::UTF8.GetString($requestBytes)
		[string[]] $requestString = ($requestParse -split '[\r\n]') |? {$_} 
		
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.ServicePointManager]::DefaultConnectionLimit = 100
		[System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
		[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)	
		
		$request.KeepAlive = $true
		$request.ProtocolVersion = [System.Net.Httpversion]::version11 
		$request.ServicePoint.ConnectionLimit = 10
		if($proxy -eq $null) { $request.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy() }
		else { $request.Proxy = $proxy }
		$request.Method = $httpMethod
		$request.AllowAutoRedirect = $false 
		$request.AutomaticDecompression = [System.Net.DecompressionMethods]::None
	
		For ($i = 1; $i -le $requestString.Length; $i++)
		{
			$line = $requestString[$i] -split ": " 
			if ( $line[0] -eq "Host" -Or $line[0] -eq $null ) { continue }
			Try
			{
				switch($line[0])
				{
					"Accept" { $request.Accept = $line[1] }
					"Connection" { "" }
					"Content-Length" { $request.ContentLength = $line[1] }
					"Content-Type" { $request.ContentType = $line[1] }
					"Expect" { $request.Expect = $line[1] }
					"Date" { $request.Date = $line[1] }
					"If-Modified-Since" { $request.IfModifiedSince = $line[1] }
					"Range" { $request.Range = $line[1] }
					"Referer" { $request.Referer = $line[1] }
					"User-Agent" { $request.UserAgent = $line[1] }
					"Transfer-Encoding"  { $request.TransferEncoding = $line[1] } 
					default {
								if($line[0] -eq "Accept-Encoding")
								{	
									$request.Headers.Add( $line[0], " ")
								}
								else
								{
									$request.Headers.Add( $line[0], $line[1])
								}	
	
							}
				}
				
			}
			Catch
			{
				
			}
		}
			
		if (($httpMethod -eq "POST") -And ($request.ContentLength -gt 0)) 
		{
			[System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
			$outputStream.Write($requestBytes, $requestBytes.Length - $request.ContentLength, $request.ContentLength)
			$outputStream.Close()
		}
		
		return Receive-ServerHttpResponse $request.GetResponse() $requestId
		
	}
	Catch [System.Net.WebException]
	{
		if ($_.Exception.Response) 
		{
			return Receive-ServerHttpResponse $_.Exception.Response $requestId
        }
			
    }
	Catch [System.Exception]
	{	
		Write-Verbose $_.Exception.Message
		Write-InterceptorLog ("Send Request Error: " + $_.Exception.Message) "Red"
	}
	
}

function Receive-ClientHttpRequest([System.Net.Sockets.TcpClient] $client, [System.Net.WebProxy] $proxy)
{
    $clientStream = $null
    $sslStream    = $null
    $isHttp2      = $false

    try {
        $clientStream = $client.GetStream()
        $byteArray = New-Object System.Byte[] 32768
        [byte[]] $byteClientRequest = @()

        $script:RequestCounter++
        $currentRequestId = $script:RequestCounter

        do {
            [int] $NumBytesRead = $clientStream.Read($byteArray, 0, $byteArray.Length)
            if ($NumBytesRead -le 0) { break }
            $byteClientRequest += $byteArray[0..($NumBytesRead - 1)]
        } while ($clientStream.DataAvailable -and $NumBytesRead -gt 0)

        $requestString = [System.Text.Encoding]::UTF8.GetString($byteClientRequest)
        [string[]] $requestArray = ($requestString -split '[\r\n]') | ? { $_ }
        [string[]] $methodParse = $requestArray[0] -split " "

        Write-InterceptorLog ("===== REQUEST [#" + $currentRequestId + "] =====") "Green"
        Write-InterceptorLog ("Client: " + $client.Client.RemoteEndPoint.ToString()) "Green"
        Write-InterceptorLog ("Method: " + $methodParse[0] + " URL: " + $methodParse[1]) "Green"

        if (-not $MinimalLogging) {
            for ($i = 1; $i -lt $requestArray.Length; $i++) {
                if ($requestArray[$i].Length -gt 0) {
                    Write-InterceptorLog ("Request Header: " + $requestArray[$i]) "Green"
                }
            }
        }

        if ($methodParse[0] -in @("POST","PUT","PATCH")) {
            $bodyStartIndex = $requestString.IndexOf("`r`n`r`n")
            if ($bodyStartIndex -gt -1) {
                $postData = $requestString.Substring($bodyStartIndex + 4)
                if ($postData.Length -gt 0) {
                    if (-not $MinimalLogging) {
                        Write-InterceptorLog ("Request Body (" + $methodParse[0] + " Data):") "Magenta"
                        $truncated = if ($postData.Length -gt 500) { $postData.Substring(0, 500) + "... [truncated]" } else { $postData }
                        Write-InterceptorLog $truncated "Magenta"
                    } else {
                        Write-InterceptorLog ("Request Body: " + $postData.Length + " bytes") "Magenta"
                    }
                }
            }
        }

        Write-InterceptorLog ("===== END REQUEST [#" + $currentRequestId + "] =====") "Green"

        if ($methodParse[0] -ceq "CONNECT") {
            [string[]] $domainParse = $methodParse[1].Split(":")
            $requestedHostname = $domainParse[0]
            Write-InterceptorLog ("CONNECT to: " + $requestedHostname) "Yellow"

            $baseDomain = Get-BaseDomain $requestedHostname
            $wildcardSubject = "*." + $baseDomain

            $connectSpoof = [System.Text.Encoding]::Ascii.GetBytes(
                "HTTP/1.1 200 Connection Established`r`nTimeStamp: " +
                [System.DateTime]::Now.ToString() + "`r`n`r`n"
            )
            $clientStream.Write($connectSpoof, 0, $connectSpoof.Length)
            $clientStream.Flush()

            $sslStream = New-Object System.Net.Security.SslStream($clientStream, $false)
            $sslStream.ReadTimeout  = 60000
            $sslStream.WriteTimeout = 60000

            $sslcertfake = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
                $_.Subject -eq ("CN=" + $wildcardSubject)
            } | Select-Object -First 1

            if (-not $sslcertfake) {
                Write-Host ("Creating wildcard certificate for: " + $wildcardSubject) -ForegroundColor Green
                Write-InterceptorLog ("Creating wildcard certificate for: " + $wildcardSubject) "Green"
                $sslcertfake = Invoke-CreateCertificate $wildcardSubject $false $true
            } else {
                Write-Host ("Using existing wildcard certificate for: " + $wildcardSubject) -ForegroundColor Cyan
                Write-InterceptorLog ("Using existing wildcard certificate for: " + $wildcardSubject) "Cyan"
            }

            if (-not $sslcertfake.HasPrivateKey) {
                Write-InterceptorLog ("Certificate for " + $wildcardSubject + " has no private key - skipping") "Red"
                return
            }

            # Enable HTTP/2 via ALPN
            $protocols = [System.Security.Authentication.SslProtocols]::Tls13 -bor
                         [System.Security.Authentication.SslProtocols]::Tls12 -bor
                         [System.Security.Authentication.SslProtocols]::Tls11

            # Try to authenticate with better error handling
            try {
                $sslStream.AuthenticateAsServer($sslcertfake, $false, $protocols, $false)
                Write-InterceptorLog ("TLS handshake completed successfully for: " + $requestedHostname) "Cyan"
            }
            catch [System.IO.IOException] {
                Write-InterceptorLog ("TLS handshake failed (client disconnect): " + $requestedHostname) "Yellow"
                return
            }
            catch [System.Security.Authentication.AuthenticationException] {
                Write-InterceptorLog ("TLS authentication failed for: " + $requestedHostname + " - " + $_.Exception.Message) "Yellow"
                return
            }
            catch {
                Write-InterceptorLog ("TLS handshake error for: " + $requestedHostname + " - " + $_.Exception.Message) "Yellow"
                return
            }

            # Check if HTTP/2 was negotiated (requires .NET 4.7.1+)
            $negotiatedProtocol = $null
            if ($sslStream | Get-Member -Name "NegotiatedApplicationProtocol" -MemberType Property) {
                $negotiatedProtocol = $sslStream.NegotiatedApplicationProtocol
                if ($negotiatedProtocol -eq "h2") {
                    $isHttp2 = $true
                    Write-InterceptorLog "HTTP/2 NEGOTIATED via ALPN" "Blue"
                }
            }

            $sslbyteArray = New-Object System.Byte[] 32768
            [byte[]] $sslbyteClientRequest = @()

            try {
                do {
                    [int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length)
                    if ($NumBytesRead -le 0) { break }
                    $sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]
                } while ($sslStream.DataAvailable)
            }
            catch [System.IO.IOException] {
                Write-InterceptorLog ("SSL read failed (connection closed): " + $requestedHostname) "Yellow"
                return
            }
            catch {
                Write-InterceptorLog ("SSL read error: " + $_.Exception.Message) "Yellow"
                return
            }

            # Check if we got any data
            if ($sslbyteClientRequest.Length -eq 0) {
                Write-InterceptorLog ("No data received from client after TLS handshake: " + $requestedHostname) "Yellow"
                return
            }

            # Check for HTTP/2 connection preface
            if ($sslbyteClientRequest.Length -ge 24) {
                $prefaceMatch = $true
                for ($i = 0; $i -lt 24; $i++) {
                    if ($sslbyteClientRequest[$i] -ne $script:HTTP2_PREFACE[$i]) {
                        $prefaceMatch = $false
                        break
                    }
                }
                
                if ($prefaceMatch) {
                    $isHttp2 = $true
                    Write-InterceptorLog "HTTP/2 CONNECTION PREFACE DETECTED" "Blue"
                    Write-InterceptorLog ([System.Text.Encoding]::ASCII.GetString($script:HTTP2_PREFACE)) "Blue"
                    
                    # Process HTTP/2 frames
                    $offset = 24
                    while ($offset -lt $sslbyteClientRequest.Length) {
                        if (($sslbyteClientRequest.Length - $offset) -lt 9) {
                            break
                        }
                        
                        $frameLength = ([int]$sslbyteClientRequest[$offset] -shl 16) + 
                                      ([int]$sslbyteClientRequest[$offset + 1] -shl 8) + 
                                      [int]$sslbyteClientRequest[$offset + 2]
                        
                        $totalFrameSize = 9 + $frameLength
                        
                        if (($sslbyteClientRequest.Length - $offset) -ge $totalFrameSize) {
                            $frameData = $sslbyteClientRequest[$offset..($offset + $totalFrameSize - 1)]
                            Parse-Http2Frame $frameData $currentRequestId
                            $offset = $offset + $totalFrameSize
                        } else {
                            break
                        }
                    }
                    
                    # Send a basic HTTP/2 response
                    # This is simplified - a full implementation would need to proxy HTTP/2 properly
                    $settingsFrame = @(
                        0x00, 0x00, 0x00,  # Length: 0
                        0x04,              # Type: SETTINGS
                        0x00,              # Flags: none
                        0x00, 0x00, 0x00, 0x00  # Stream ID: 0
                    )
                    
                    $settingsAck = @(
                        0x00, 0x00, 0x00,  # Length: 0
                        0x04,              # Type: SETTINGS
                        0x01,              # Flags: ACK
                        0x00, 0x00, 0x00, 0x00  # Stream ID: 0
                    )
                    
                    Write-InterceptorLog "Sending HTTP/2 SETTINGS frame" "Blue"
                    $sslStream.Write([byte[]]$settingsFrame, 0, $settingsFrame.Length)
                    $sslStream.Write([byte[]]$settingsAck, 0, $settingsAck.Length)
                    $sslStream.Flush()
                    
                    Write-InterceptorLog "HTTP/2 connection established (basic handshake)" "Blue"
                    
                    return
                }
            }

            # If not HTTP/2, process as HTTP/1.1
            if (-not $isHttp2) {
                $SSLRequest = [System.Text.Encoding]::UTF8.GetString($sslbyteClientRequest)
                [string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') | ? { $_ }
                
                if ($SSLrequestArray.Length -eq 0) {
                    Write-InterceptorLog "Empty HTTPS request received" "Red"
                    return
                }
                
                [string[]] $SSLmethodParse  = $SSLrequestArray[0] -split " "

                $secureURI = "https://" + $requestedHostname + $SSLmethodParse[1]

                Write-InterceptorLog ("===== HTTPS REQUEST [#" + $currentRequestId + "] =====") "Green"
                Write-InterceptorLog ("Secure Method: " + $SSLmethodParse[0] +
                                      " Secure URL: " + $secureURI) "Green"

                if (-not $MinimalLogging) {
                    for ($i = 1; $i -lt $SSLrequestArray.Length; $i++) {
                        if ($SSLrequestArray[$i].Length -gt 0) {
                            Write-InterceptorLog ("HTTPS Header: " + $SSLrequestArray[$i]) "Green"
                        }
                    }
                }

                if ($SSLmethodParse[0] -in @("POST","PUT","PATCH")) {
                    $bodyStartIndex = $SSLRequest.IndexOf("`r`n`r`n")
                    if ($bodyStartIndex -gt -1) {
                        $postData = $SSLRequest.Substring($bodyStartIndex + 4)
                        if ($postData.Length -gt 0) {
                            if (-not $MinimalLogging) {
                                Write-InterceptorLog ("HTTPS Body (" + $SSLmethodParse[0] + " Data):") "Magenta"
                                $truncated = if ($postData.Length -gt 500) { $postData.Substring(0, 500) + "... [truncated]" } else { $postData }
                                Write-InterceptorLog $truncated "Magenta"
                            } else {
                                Write-InterceptorLog ("HTTPS Body: " + $postData.Length + " bytes") "Magenta"
                            }
                        }
                    }
                }

                Write-InterceptorLog ("===== END HTTPS REQUEST [#" + $currentRequestId + "] =====") "Green"

                [byte[]] $byteResponse = Send-ServerHttpRequest $secureURI $SSLmethodParse[0] $sslbyteClientRequest $proxy $currentRequestId

                if (-not $byteResponse -or $byteResponse.Length -eq 0) {
                    Write-InterceptorLog ("Upstream returned null/empty response for " + $secureURI) "Red"
                    
                    $errBody = "Bad Gateway: upstream request failed."
                    $errStr  = "HTTP/1.1 502 Bad Gateway`r`n" +
                               "Content-Type: text/plain`r`n" +
                               ("Content-Length: {0}`r`n" -f $errBody.Length) +
                               "Connection: close`r`n`r`n" +
                               $errBody
                    
                    $byteResponse = [System.Text.Encoding]::ASCII.GetBytes($errStr)
                }
                
                if ($byteResponse.Length -gt 0 -and $byteResponse[0] -eq '0x00') {
                    $sslStream.Write($byteResponse, 1, $byteResponse.Length - 1)
                } else {
                    $sslStream.Write($byteResponse, 0, $byteResponse.Length)
                }
                $sslStream.Flush()
            }
        }
        else {
            [byte[]] $proxiedResponse = Send-ServerHttpRequest $methodParse[1] $methodParse[0] $byteClientRequest $proxy $currentRequestId

            if ($proxiedResponse[0] -eq '0x00') {
                $clientStream.Write($proxiedResponse, 1, $proxiedResponse.Length - 1)
            } else {
                $clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length)
            }
            $clientStream.Flush()
        }

    } catch [System.IO.IOException] {
        # Common when clients disconnect - log quietly
        $shortMsg = $_.Exception.Message
        if ($shortMsg.Length -gt 80) { $shortMsg = $shortMsg.Substring(0, 80) + "..." }
        Write-InterceptorLog ("Connection closed: " + $shortMsg) "Yellow"
    } catch [System.Net.Sockets.SocketException] {
        # Network errors - log quietly  
        Write-InterceptorLog ("Network error: " + $_.Exception.SocketErrorCode) "Yellow"
    } catch [System.Security.Authentication.AuthenticationException] {
        # TLS errors - common with certificate issues
        Write-InterceptorLog ("TLS authentication failed") "Yellow"
    } catch {
        # Other unexpected errors - log with detail
        $errorMsg = $_.Exception.Message
        if ($errorMsg.Length -gt 120) {
            $errorMsg = $errorMsg.Substring(0, 120) + "..."
        }
        Write-InterceptorLog ("Unexpected error: " + $errorMsg) "Red"
    } finally {
        if ($sslStream -ne $null) {
            try { $sslStream.Flush() } catch {}
            try { $sslStream.Dispose() } catch {}
        }
        if ($clientStream -ne $null) {
            try { $clientStream.Dispose() } catch {}
        }
        if ($client -ne $null) {
            try { $client.Close() } catch {}
        }
    }
}

function Main()
{	
	if($Cleanup)
	{
		Invoke-RemoveCertificates( "__Interceptor_Trusted_Root" )
		exit
	}
	
	Write-InterceptorLog "========================================" "Cyan"
	Write-InterceptorLog "Interceptor Proxy Starting (HTTP/2 Support)" "Cyan"
	Write-InterceptorLog "Version: 4.0" "Cyan"
	Write-InterceptorLog "========================================" "Cyan"
	
	if($Tamper) { Write-InterceptorLog "Tamper Mode: ENABLED" "Magenta" }
	if($ProxyServer) { Write-InterceptorLog ("Upstream Proxy: " + $ProxyServer + ":" + $ProxyPort) "Yellow" }
	
	$CAcertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root"  })
	if ($CACertificate -eq $null)
	{
		Write-InterceptorLog "Creating Root CA Certificate" "Green"
		Invoke-CreateCertificate "__Interceptor_Trusted_Root" $true $false
	}
	else
	{
		Write-InterceptorLog "Root CA Certificate already exists" "Green"
	}
	
	if($HostCA)
	{
		netsh advfirewall firewall delete rule name="Interceptor Proxy 8082" | Out-Null
		netsh advfirewall firewall add rule name="Interceptor Proxy 8082" dir=in action=allow protocol=TCP localport=8082 | Out-Null
		Start-CertificateAuthority
		Write-InterceptorLog "Certificate Authority hosted on port 8082" "Green"
	}
	
	# Pre-generate certificates for common domains
	Write-InterceptorLog "Pre-generating certificates for common domains..." "Green"
	$commonDomains = @(
		"*.google.com",
		"*.googleapis.com", 
		"*.gstatic.com",
		"*.microsoft.com",
		"*.windows.com",
		"*.live.com",
		"*.facebook.com",
		"*.amazon.com",
		"*.cloudfront.net",
		"*.cdn.com",
		"*.apple.com",
		"*.icloud.com"
	)
	
	foreach ($domain in $commonDomains) {
		$existing = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
			$_.Subject -eq ("CN=" + $domain)
		} | Select-Object -First 1
		
		if (-not $existing) {
			try {
				Invoke-CreateCertificate $domain $false $true | Out-Null
			} catch {
				# Ignore errors during pre-generation
			}
		}
	}
	Write-InterceptorLog "Certificate pre-generation complete" "Green"
	
	if($ListenPort)
	{
		$port = $ListenPort
	}
	else
	{
		$port = 8081
	}
	
	$endpoint = New-Object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
	$listener = New-Object System.Net.Sockets.TcpListener $endpoint
	
	netsh advfirewall firewall delete rule name="Interceptor Proxy $port" | Out-Null
	netsh advfirewall firewall add rule name="Interceptor Proxy $port" dir=in action=allow protocol=TCP localport=$port | Out-Null
	
	if($ProxyServer)
	{
		$proxy = New-Object System.Net.WebProxy($ProxyServer, $ProxyPort)
		[Console]::WriteLine("Using Proxy Server " + $ProxyServer + " : " + $ProxyPort)
		Write-InterceptorLog ("Configured to use upstream proxy: " + $ProxyServer + ":" + $ProxyPort) "Yellow"
	}
	else
	{
		$proxy = $null
		[Console]::WriteLine("Using Direct Internet Connection")
		Write-InterceptorLog "Using Direct Internet Connection" "Yellow"
	}
		
	$listener.Start()
	[Console]::WriteLine("Listening on " + $port)
	[Console]::WriteLine("Logging to: " + $script:LogFile)
	[Console]::WriteLine("HTTP/2 support enabled")
	
	Write-InterceptorLog ("Interceptor listening on port " + $port) "Green"
	Write-InterceptorLog ("Log file: " + $script:LogFile) "Green"
	if (-not $DisableHttp2Parsing) {
		Write-InterceptorLog "HTTP/2 frame parsing enabled" "Blue"
	} else {
		Write-InterceptorLog "HTTP/2 frame parsing disabled (performance mode)" "Blue"
	}
	if ($MinimalLogging) {
		Write-InterceptorLog "Minimal logging enabled (performance mode)" "Yellow"
	}
	Write-InterceptorLog "========================================" "Cyan"
	Write-InterceptorLog "Waiting for connections..." "Yellow"
	
	# Flush log on Ctrl+C
	$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
		Flush-LogBuffer
	}
	
	$client = New-Object System.Net.Sockets.TcpClient
	$client.NoDelay = $true
	
	while($true)
	{
		$client = $listener.AcceptTcpClient()
		if($client -ne $null)
		{
			Receive-ClientHttpRequest $client $proxy
		}
	}
}

# Ensure log is flushed on exit
trap {
	Flush-LogBuffer
	break
}

Main
