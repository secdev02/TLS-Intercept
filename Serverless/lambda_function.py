import json
import urllib.parse
import urllib.request
import ssl
import socket
import re
import base64
from datetime import datetime

def replace_content(html_content):
    """
    Replace specific content for testing/prod environments
    """
    # Replace 'army' with 'navy' (case-insensitive)
    html_content = re.sub(r'\barmy\b', 'navy', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'\bArmy\b', 'Navy', html_content)
    html_content = re.sub(r'\bARMY\b', 'NAVY', html_content)
    
    return html_content

def rewrite_urls(html_content, original_url, proxy_base_url):
    """
    Rewrite all URLs in HTML to go through the proxy
    Skip analytics and tracking URLs
    """
    parsed_original = urllib.parse.urlparse(original_url)
    base_url = parsed_original.scheme + '://' + parsed_original.netloc
    
    # URLs that should NOT be proxied (analytics, tracking, etc.)
    skip_patterns = [
        '/gen_204',  # Google analytics
        '/pagead/',  # Google ads
        '/log?',     # Logging endpoints
        'google-analytics.com',
        'googletagmanager.com',
        'doubleclick.net',
    ]
    
    # Function to convert URL to proxied version
    def to_proxy_url(url):
        if not url or url.startswith('data:') or url.startswith('javascript:') or url.startswith('#'):
            return url
        
        # Skip analytics/tracking URLs
        for pattern in skip_patterns:
            if pattern in url:
                return url
        
        # Make absolute
        if url.startswith('//'):
            url = parsed_original.scheme + ':' + url
        elif url.startswith('/'):
            url = base_url + url
        elif not url.startswith('http'):
            # Relative URL
            url = urllib.parse.urljoin(original_url, url)
        
        # Skip if still matches patterns after making absolute
        for pattern in skip_patterns:
            if pattern in url:
                return url
        
        # Convert to proxy URL - always use /debug path
        return proxy_base_url + '/debug?url=' + urllib.parse.quote(url, safe='') + '&inline=true'
    
    # Rewrite src attributes (img, script, iframe, etc.) - handle both " and '
    html_content = re.sub(
        r'(<(?:img|script|iframe|embed|source|track|video|audio)[^>]*\s+src=")([^"]+)(")',
        lambda m: m.group(1) + to_proxy_url(m.group(2)) + m.group(3),
        html_content,
        flags=re.IGNORECASE
    )
    html_content = re.sub(
        r"(<(?:img|script|iframe|embed|source|track|video|audio)[^>]*\s+src=')([^']+)(')",
        lambda m: m.group(1) + to_proxy_url(m.group(2)) + m.group(3),
        html_content,
        flags=re.IGNORECASE
    )
    
    # Rewrite href attributes (link, a) - handle both " and '
    html_content = re.sub(
        r'(<(?:link|a|area)[^>]*\s+href=")([^"]+)(")',
        lambda m: m.group(1) + to_proxy_url(m.group(2)) + m.group(3),
        html_content,
        flags=re.IGNORECASE
    )
    html_content = re.sub(
        r"(<(?:link|a|area)[^>]*\s+href=')([^']+)(')",
        lambda m: m.group(1) + to_proxy_url(m.group(2)) + m.group(3),
        html_content,
        flags=re.IGNORECASE
    )
    
    # Rewrite data-src attributes (lazy loading)
    html_content = re.sub(
        r'(<[^>]*\s+data-src=")([^"]+)(")',
        lambda m: m.group(1) + to_proxy_url(m.group(2)) + m.group(3),
        html_content,
        flags=re.IGNORECASE
    )
    html_content = re.sub(
        r"(<[^>]*\s+data-src=')([^']+)(')",
        lambda m: m.group(1) + to_proxy_url(m.group(2)) + m.group(3),
        html_content,
        flags=re.IGNORECASE
    )
    
    # Rewrite CSS url() references
    html_content = re.sub(
        r'url\(["\']?([^"\')]+)["\']?\)',
        lambda m: 'url("' + to_proxy_url(m.group(1)) + '")',
        html_content,
        flags=re.IGNORECASE
    )
    
    # Rewrite srcset attributes
    def rewrite_srcset(match):
        srcset = match.group(2)
        new_srcset = []
        for item in srcset.split(','):
            parts = item.strip().split()
            if parts:
                parts[0] = to_proxy_url(parts[0])
                new_srcset.append(' '.join(parts))
        return match.group(1) + ', '.join(new_srcset) + match.group(3)
    
    html_content = re.sub(
        r'(<[^>]*\s+srcset=")([^"]+)(")',
        rewrite_srcset,
        html_content,
        flags=re.IGNORECASE
    )
    html_content = re.sub(
        r"(<[^>]*\s+srcset=')([^']+)(')",
        rewrite_srcset,
        html_content,
        flags=re.IGNORECASE
    )
    
    return html_content

def lambda_handler(event, context):
    """
    AWS Lambda handler for TLS debugging reverse proxy
    Supports GET and POST requests, cookie forwarding, and workflow debugging
    """
    
    # Get HTTP method
    http_method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    
    # Handle OPTIONS preflight for CORS
    if http_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Max-Age': '86400',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': ''
        }
    
    # Parse query parameters - handle both 'url' and 'site' parameters for compatibility
    query_params = event.get('queryStringParameters', {})
    if not query_params:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Missing required parameter: url',
                'usage': 'Add ?url=https://example.com to the URL'
            })
        }
    
    # Accept both 'url' and 'site' parameters for backward compatibility
    target_site = query_params.get('url') or query_params.get('site')
    if not target_site:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Missing required parameter: url or site',
                'usage': 'Add ?url=https://example.com to the URL'
            })
        }
    
    inline_mode = query_params.get('inline', '').lower() in ['true', '1', 'yes']
    trace_mode = query_params.get('trace', '').lower() in ['true', '1', 'yes']
    
    # Always use api.tlsdebug.com as proxy base URL
    proxy_base_url = 'https://api.tlsdebug.com'
    
    # Clean up the site URL - add https:// if no scheme provided
    if not target_site.startswith('http'):
        target_site = 'https://' + target_site
    
    try:
        parsed_url = urllib.parse.urlparse(target_site)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        path = parsed_url.path or '/'
        
        # Prepare the request
        request_url = target_site if parsed_url.path else target_site + '/'
        
        # Get POST data if present
        post_data = None
        content_type = None
        if http_method == 'POST':
            # Get body from event
            body = event.get('body', '')
            if event.get('isBase64Encoded', False):
                post_data = base64.b64decode(body)
            else:
                post_data = body.encode('utf-8') if body else None
            
            # Get content type from headers
            headers = event.get('headers', {})
            content_type = headers.get('content-type') or headers.get('Content-Type')
        
        # Create request
        req = urllib.request.Request(request_url, data=post_data, method=http_method)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
        req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8')
        req.add_header('Accept-Language', 'en-US,en;q=0.9')
        req.add_header('Referer', parsed_url.scheme + '://' + parsed_url.netloc + '/')
        
        # Forward cookies from client to server
        request_headers = event.get('headers', {})
        if 'cookie' in request_headers or 'Cookie' in request_headers:
            cookie_header = request_headers.get('cookie') or request_headers.get('Cookie')
            req.add_header('Cookie', cookie_header)
        
        # Add Content-Type for POST
        if content_type and http_method == 'POST':
            req.add_header('Content-Type', content_type)
        
        # Initialize trace log
        trace_log = []
        if trace_mode:
            trace_log.append({
                'event': 'request_start',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'url': request_url,
                'method': http_method
            })
        
        # Capture request details
        request_details = {
            'method': http_method,
            'url': request_url,
            'headers': dict(req.headers),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        if post_data:
            request_details['body_size'] = len(post_data)
            request_details['content_type'] = content_type
        
        # Create custom SSL context with lower security for debugging
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Don't verify certificates for debugging
        ctx.set_ciphers('ALL:@SECLEVEL=0')  # Allow all ciphers including weak ones
        
        # Make the connection
        start_time = datetime.utcnow()
        
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            # Calculate duration
            end_time = datetime.utcnow()
            duration_ms = (end_time - start_time).total_seconds() * 1000
            
            if trace_mode:
                trace_log.append({
                    'event': 'response_received',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'status': response.status,
                    'duration_ms': duration_ms
                })
            
            # Get TLS/SSL information
            sock = response.fp.raw._sock
            cipher = sock.cipher() if hasattr(sock, 'cipher') else None
            cert = sock.getpeercert() if hasattr(sock, 'getpeercert') else None
            
            # Read response
            response_data = response.read()
            content_type = response.headers.get('Content-Type', '')
            
            if trace_mode:
                trace_log.append({
                    'event': 'response_read',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'content_type': content_type,
                    'size': len(response_data)
                })
            
            # Decode if text
            is_text = any(t in content_type.lower() for t in ['text/', 'application/json', 'application/xml', 'application/javascript', '+xml', '+json'])
            
            if is_text:
                # Try to decode as text
                try:
                    body = response_data.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        body = response_data.decode('latin-1')
                    except:
                        # If all else fails, treat as binary
                        is_text = False
            
            # If inline mode is enabled, return the content directly
            if inline_mode:
                # For HTML, rewrite URLs to proxy
                if 'text/html' in content_type and is_text:
                    if trace_mode:
                        trace_log.append({
                            'event': 'rewriting_urls',
                            'timestamp': datetime.utcnow().isoformat() + 'Z'
                        })
                    
                    body = rewrite_urls(body, request_url, proxy_base_url)
                    
                    # Apply content replacements (army -> navy)
                    body = replace_content(body)
                    
                    # Inject JavaScript for debugging and URL interception
                    debug_script = """
<script>
// TLS Debug - Intercept fetch and XHR requests
(function() {
    console.log('=== TLS Debug Inline Mode ===');
    console.log('Original URL:', '""" + request_url + """');
    console.log('Original Origin:', new URL('""" + request_url + """').origin);
    console.log('All resources are being proxied');
    console.log('Proxy URL:', window.location.href);
    
    const PROXY_BASE = '""" + proxy_base_url + """';
    const ORIGINAL_ORIGIN = new URL('""" + request_url + """').origin;
    
    // Skip these patterns - don't proxy analytics
    const SKIP_PATTERNS = ['/gen_204', '/pagead/', '/log?', 'google-analytics.com', 'googletagmanager.com', 'doubleclick.net'];
    
    function shouldSkip(url) {
        return SKIP_PATTERNS.some(pattern => url.includes(pattern));
    }
    
    function proxyUrl(url) {
        if (!url || url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:') || shouldSkip(url)) {
            return url;
        }
        
        // Make absolute
        if (url.startsWith('//')) {
            url = window.location.protocol + url;
        } else if (url.startsWith('/')) {
            url = ORIGINAL_ORIGIN + url;
        } else if (!url.startsWith('http')) {
            url = new URL(url, '""" + request_url + """').href;
        }
        
        // Check again after making absolute
        if (shouldSkip(url)) {
            return url;
        }
        
        return PROXY_BASE + '/debug?url=' + encodeURIComponent(url) + '&inline=true';
    }
    
    // Intercept fetch
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        const proxiedUrl = proxyUrl(url);
        console.log('Fetch intercepted:', url, '->', proxiedUrl);
        return originalFetch(proxiedUrl, options);
    };
    
    // Intercept XMLHttpRequest
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...args) {
        const proxiedUrl = proxyUrl(url);
        console.log('XHR intercepted:', url, '->', proxiedUrl);
        return originalOpen.call(this, method, proxiedUrl, ...args);
    };
    
    // Intercept dynamic script/link/img creation
    const originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if ((name === 'src' || name === 'href') && typeof value === 'string') {
            const proxiedValue = proxyUrl(value);
            if (proxiedValue !== value) {
                console.log('Property ' + name + ' set:', proxiedValue);
            }
            return originalSetAttribute.call(this, name, proxiedValue);
        }
        return originalSetAttribute.call(this, name, value);
    };
    
    console.log('Debug logging and URL interception enabled');
    console.log('=============================');
})();
</script>
"""
                    # Inject before </body> or at end
                    if '</body>' in body:
                        body = body.replace('</body>', debug_script + '</body>')
                    else:
                        body += debug_script
                    
                    response_headers = {
                        'Content-Type': content_type,
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                        'Access-Control-Allow-Headers': '*',
                        'X-Frame-Options': 'ALLOWALL',
                        'Content-Security-Policy': "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; img-src * data: blob:; font-src * data:; connect-src *; frame-src *;"
                    }
                    
                    # Forward Set-Cookie headers if present
                    set_cookie_headers = response.headers.get_all('Set-Cookie')
                    if set_cookie_headers:
                        return {
                            'statusCode': response.status,
                            'headers': response_headers,
                            'multiValueHeaders': {
                                'Set-Cookie': set_cookie_headers
                            },
                            'body': body
                        }
                    
                    return {
                        'statusCode': response.status,
                        'headers': response_headers,
                        'body': body
                    }
                
                # For CSS, rewrite URLs
                if 'text/css' in content_type and is_text:
                    def rewrite_css_url(match):
                        url = match.group(1).strip('\'"')
                        if url.startswith('data:') or url.startswith('#'):
                            return match.group(0)
                        # Make absolute
                        if url.startswith('//'):
                            url = parsed_url.scheme + ':' + url
                        elif url.startswith('/'):
                            url = parsed_url.scheme + '://' + parsed_url.netloc + url
                        elif not url.startswith('http'):
                            url = urllib.parse.urljoin(request_url, url)
                        # Proxy it
                        proxy_url = proxy_base_url + '/debug?url=' + urllib.parse.quote(url, safe='') + '&inline=true'
                        return 'url("' + proxy_url + '")'
                    
                    body = re.sub(r'url\(([^)]+)\)', rewrite_css_url, body)
                    
                    return {
                        'statusCode': response.status,
                        'headers': {
                            'Content-Type': content_type,
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                            'Access-Control-Allow-Headers': '*',
                        },
                        'body': body
                    }
                
                # For binary content (images, fonts, etc.), return as base64
                if not is_text:
                    body_base64 = base64.b64encode(response_data).decode('utf-8')
                    return {
                        'statusCode': response.status,
                        'headers': {
                            'Content-Type': content_type,
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                            'Access-Control-Allow-Headers': '*',
                        },
                        'body': body_base64,
                        'isBase64Encoded': True
                    }
                
                # For other text content (JS, etc.), return as-is
                return {
                    'statusCode': response.status,
                    'headers': {
                        'Content-Type': content_type,
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                        'Access-Control-Allow-Headers': '*',
                    },
                    'body': body
                }
            
            # Non-inline mode: return JSON debug info
            response_details = {
                'status_code': response.status,
                'status_message': response.reason,
                'headers': dict(response.headers),
                'body_preview': body[:1000] if is_text else base64.b64encode(response_data[:1000]).decode('utf-8'),
                'body_size': len(response_data),
                'truncated': len(response_data) > 1000,
                'duration_ms': duration_ms,
                'is_binary': not is_text
            }
            
            if trace_mode:
                trace_log.append({
                    'event': 'processing_complete',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'body_size': len(response_data),
                    'content_type': content_type
                })
            
            # TLS/SSL details
            tls_details = {
                'protocol': cipher[1] if cipher else 'Unknown',
                'cipher': cipher[0] if cipher else 'Unknown',
                'bits': cipher[2] if cipher and len(cipher) > 2 else 'Unknown',
                'certificate': {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'san': cert.get('subjectAltName', [])
                } if cert else None
            }
            
            # Build response object
            response_object = {
                'request': request_details,
                'response': response_details,
                'tls': tls_details,
                'success': True
            }
            
            if trace_mode:
                response_object['trace'] = trace_log
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(response_object, indent=2)
            }
            
    except urllib.error.HTTPError as e:
        # If inline mode, try to return error page HTML
        if inline_mode:
            try:
                error_body = e.read().decode('utf-8', errors='replace')
                return {
                    'statusCode': e.code,
                    'headers': {
                        'Content-Type': 'text/html',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': error_body
                }
            except:
                return {
                    'statusCode': e.code,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': str(e.reason)
                }
        
        # JSON error response
        error_response = {
            'request': request_details if 'request_details' in locals() else {},
            'response': {
                'status_code': e.code,
                'status_message': e.reason,
                'headers': dict(e.headers) if hasattr(e, 'headers') else {},
                'error': str(e)
            },
            'success': False
        }
        
        if 'trace_log' in locals() and trace_mode:
            error_response['trace'] = trace_log
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(error_response, indent=2)
        }
        
    except Exception as e:
        # Build error response
        error_response = {
            'error': str(e),
            'error_type': type(e).__name__,
            'success': False
        }
        
        if 'trace_log' in locals() and trace_mode:
            trace_log.append({
                'event': 'error',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'error_type': type(e).__name__,
                'error_message': str(e)
            })
            error_response['trace'] = trace_log
        
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(error_response, indent=2)
        }
