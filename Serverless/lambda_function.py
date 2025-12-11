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
    Preserves case for all replacements
    """
    def replace_army(match):
        original = match.group(0)
        if original.isupper():
            return 'NAVY'
        elif original[0].isupper():
            return 'Navy'
        else:
            return 'navy'
    
    def replace_cyber(match):
        original = match.group(0)
        if original.isupper():
            return 'KITTEN'
        elif original[0].isupper():
            return 'Kitten'
        else:
            return 'kitten'
    
    html_content = re.sub(r'\barmy\b', replace_army, html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'\bcyber\b', replace_cyber, html_content, flags=re.IGNORECASE)
    return html_content

def rewrite_urls(html_content, original_url, proxy_base_url):
    """
    Rewrite all URLs in HTML to go through the proxy
    Skip analytics and tracking URLs
    """
    try:
        parsed_original = urllib.parse.urlparse(original_url)
        base_url = f"{parsed_original.scheme}://{parsed_original.netloc}"
        
        # URLs that should NOT be proxied (analytics, tracking, etc.)
        skip_patterns = [
            '/gen_204',
            '/pagead/',
            '/log?',
            'google-analytics.com',
            'googletagmanager.com',
            'doubleclick.net',
            'googleadservices.com',
            '/analytics/',
            '/tracking/',
        ]
        
        def to_proxy_url(url):
            if not url or url.startswith(('data:', 'javascript:', 'mailto:', 'tel:', '#', 'blob:')):
                return url
            
            # Skip analytics/tracking URLs
            for pattern in skip_patterns:
                if pattern in url:
                    return url
            
            # Make absolute
            try:
                if url.startswith('//'):
                    url = f"{parsed_original.scheme}:{url}"
                elif url.startswith('/'):
                    url = f"{base_url}{url}"
                elif not url.startswith('http'):
                    url = urllib.parse.urljoin(original_url, url)
            except Exception as e:
                print(f"URL parse error: {e} for url: {url}")
                return url
            
            # Skip if matches patterns after making absolute
            for pattern in skip_patterns:
                if pattern in url:
                    return url
            
            # Convert to proxy URL
            return f"{proxy_base_url}/debug?url={urllib.parse.quote(url, safe='')}&inline=true"
        
        # Rewrite src attributes
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
        
        # Rewrite href attributes
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
            lambda m: f'url("{to_proxy_url(m.group(1))}")',
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
    except Exception as e:
        print(f"Error in rewrite_urls: {e}")
        return html_content

def lambda_handler(event, context):
    """
    AWS Lambda handler for TLS debugging reverse proxy
    Supports GET and POST requests, cookie forwarding, and workflow debugging
    """
    
    try:
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
        
        # Parse query parameters
        query_params = event.get('queryStringParameters') or {}
        
        # Accept both 'url' and 'site' parameters
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
                    'usage': 'Add ?url=https://example.com to the URL',
                    'example': 'https://api.tlsdebug.com/debug?url=https://example.com&inline=true'
                })
            }
        
        inline_mode = query_params.get('inline', '').lower() in ['true', '1', 'yes']
        trace_mode = query_params.get('trace', '').lower() in ['true', '1', 'yes']
        
        # Get request path from multiple possible locations
        request_context = event.get('requestContext', {})
        
        # Try rawPath first (HTTP API), then path (REST API)
        raw_path = event.get('rawPath') or request_context.get('path') or '/debug'
        domain_name = request_context.get('domainName', 'api.tlsdebug.com')
        
        print(f"DEBUG: raw_path from event={raw_path}")
        
        # If path includes stage (e.g., /prod/nest/debug), remove it
        # Common stages: prod, dev, test, stage
        for stage_name in ['prod', 'dev', 'test', 'stage']:
            if raw_path.startswith(f'/{stage_name}/'):
                raw_path = raw_path[len(stage_name) + 1:]  # Keep the leading /
                print(f"DEBUG: Removed /{stage_name}, new path={raw_path}")
                break
        
        # Extract everything before /debug
        if '/debug' in raw_path:
            path_prefix = raw_path.split('/debug')[0]
        else:
            path_prefix = ''
        
        print(f"DEBUG: path_prefix={path_prefix}, domain={domain_name}")
        
        # Build proxy base URL
        proxy_base_url = f'https://{domain_name}{path_prefix}'
        print(f"DEBUG: proxy_base_url={proxy_base_url}")
        
        # Clean up the site URL
        if not target_site.startswith('http'):
            target_site = f"https://{target_site}"
        
        parsed_url = urllib.parse.urlparse(target_site)
        request_url = target_site if parsed_url.path else f"{target_site}/"
        
        # Prepare POST data if present
        post_data = None
        content_type_header = None
        
        if http_method == 'POST':
            body = event.get('body', '')
            if event.get('isBase64Encoded', False):
                post_data = base64.b64decode(body)
            else:
                post_data = body.encode('utf-8') if body else None
            
            headers = event.get('headers', {})
            content_type_header = headers.get('content-type') or headers.get('Content-Type')
        
        # Create request
        req = urllib.request.Request(request_url, data=post_data, method=http_method)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
        req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8')
        req.add_header('Accept-Language', 'en-US,en;q=0.9')
        req.add_header('Referer', f"{parsed_url.scheme}://{parsed_url.netloc}/")
        
        # Forward cookies
        request_headers = event.get('headers', {})
        if 'cookie' in request_headers or 'Cookie' in request_headers:
            cookie_header = request_headers.get('cookie') or request_headers.get('Cookie')
            req.add_header('Cookie', cookie_header)
        
        if content_type_header and http_method == 'POST':
            req.add_header('Content-Type', content_type_header)
        
        # Initialize trace log
        trace_log = []
        if trace_mode:
            trace_log.append({
                'event': 'request_start',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'url': request_url,
                'method': http_method
            })
        
        request_details = {
            'method': http_method,
            'url': request_url,
            'headers': dict(req.headers),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        if post_data:
            request_details['body_size'] = len(post_data)
            request_details['content_type'] = content_type_header
        
        # Create SSL context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('ALL:@SECLEVEL=0')
        
        # Create opener that follows redirects
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        redirect_handler = urllib.request.HTTPRedirectHandler()
        opener = urllib.request.build_opener(https_handler, redirect_handler)
        
        start_time = datetime.utcnow()
        
        with opener.open(req, timeout=30) as response:
            end_time = datetime.utcnow()
            duration_ms = (end_time - start_time).total_seconds() * 1000
            
            # Get final URL after redirects
            final_url = response.geturl()
            
            if trace_mode:
                trace_log.append({
                    'event': 'response_received',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'status': response.status,
                    'duration_ms': duration_ms,
                    'final_url': final_url
                })
            
            # Get TLS info
            try:
                sock = response.fp.raw._sock
                cipher = sock.cipher() if hasattr(sock, 'cipher') else None
                cert = sock.getpeercert() if hasattr(sock, 'getpeercert') else None
            except:
                cipher = None
                cert = None
            
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
            
            # Determine if text
            is_text = any(t in content_type.lower() for t in [
                'text/', 'application/json', 'application/xml',
                'application/javascript', '+xml', '+json'
            ])
            
            if is_text:
                try:
                    body = response_data.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        body = response_data.decode('latin-1')
                    except Exception as e:
                        print(f"Decode error: {e}")
                        is_text = False
            
            # Inline mode
            if inline_mode:
                # HTML content
                if 'text/html' in content_type and is_text:
                    try:
                        if trace_mode:
                            trace_log.append({
                                'event': 'rewriting_urls',
                                'timestamp': datetime.utcnow().isoformat() + 'Z'
                            })
                        
                        # Use final_url for rewriting (handles redirects)
                        body = rewrite_urls(body, final_url, proxy_base_url)
                        body = replace_content(body)
                        
                        # Add base tag to help JavaScript dynamic imports resolve correctly
                        # Use the directory of the final URL
                        parsed_final = urllib.parse.urlparse(final_url)
                        base_url = f"{parsed_final.scheme}://{parsed_final.netloc}{parsed_final.path}"
                        if not base_url.endswith('/'):
                            # Get directory of the URL
                            base_url = base_url.rsplit('/', 1)[0] + '/'
                        
                        base_tag = f'<base href="{base_url}">'
                        if '<head>' in body:
                            body = body.replace('<head>', f'<head>\n{base_tag}', 1)
                        elif '<HEAD>' in body:
                            body = body.replace('<HEAD>', f'<HEAD>\n{base_tag}', 1)
                        
                        # Inject debug script BEFORE any other scripts
                        debug_script = f"""
<script type="module">
// Override import.meta.url and dynamic imports BEFORE any modules load
const ORIGINAL_URL = '{final_url}';
const PROXY_BASE = '{proxy_base_url}';

// Create import map
const importMap = document.createElement('script');
importMap.type = 'importmap';
importMap.textContent = JSON.stringify({{
    imports: {{}}
}});
document.head.insertBefore(importMap, document.head.firstChild);
</script>

<script>
(function() {{
    console.log('=== TLS Debug Inline Mode ===');
    console.log('Original URL:', '{request_url}');
    console.log('Final URL:', '{final_url}');
    console.log('Proxy URL:', window.location.href);
    
    const PROXY_BASE = '{proxy_base_url}';
    const ORIGINAL_URL = '{final_url}';
    const ORIGINAL_ORIGIN = new URL(ORIGINAL_URL).origin;
    const SKIP_PATTERNS = ['/gen_204', '/pagead/', '/log?', 'google-analytics.com', 'googletagmanager.com', 'doubleclick.net'];
    
    // Override document.baseURI for JS that reads it
    Object.defineProperty(document, 'baseURI', {{
        get: function() {{ return ORIGINAL_URL; }},
        configurable: true
    }});
    
    // Override window.location properties (read-only proxy)
    const realLocation = window.location;
    const fakeLocation = new URL(ORIGINAL_URL);
    
    try {{
        Object.defineProperty(window, 'location', {{
            get: function() {{
                return new Proxy(realLocation, {{
                    get: function(target, prop) {{
                        if (prop === 'href') return ORIGINAL_URL;
                        if (prop === 'origin') return ORIGINAL_ORIGIN;
                        if (prop === 'host') return fakeLocation.host;
                        if (prop === 'hostname') return fakeLocation.hostname;
                        if (prop === 'pathname') return fakeLocation.pathname;
                        if (prop === 'search') return fakeLocation.search;
                        if (prop === 'hash') return fakeLocation.hash;
                        return target[prop];
                    }}
                }});
            }},
            configurable: true
        }});
    }} catch(e) {{ console.warn('Could not override location:', e); }}
    
    function shouldSkip(url) {{
        return SKIP_PATTERNS.some(pattern => url.includes(pattern));
    }}
    
    function proxyUrl(url) {{
        if (!url || url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:') || shouldSkip(url)) {{
            return url;
        }}
        
        // Resolve relative to ORIGINAL_URL, not proxy URL
        if (url.startsWith('//')) {{
            url = fakeLocation.protocol + url;
        }} else if (url.startsWith('/')) {{
            url = ORIGINAL_ORIGIN + url;
        }} else if (!url.startsWith('http')) {{
            url = new URL(url, ORIGINAL_URL).href;
        }}
        
        if (shouldSkip(url)) {{
            return url;
        }}
        
        return PROXY_BASE + '/debug?url=' + encodeURIComponent(url) + '&inline=true';
    }}
    
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {{}}) {{
        const proxiedUrl = proxyUrl(url);
        if (proxiedUrl !== url) {{
            console.log('Fetch:', url, '->', proxiedUrl);
        }}
        return originalFetch(proxiedUrl, options);
    }};
    
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...args) {{
        const proxiedUrl = proxyUrl(url);
        if (proxiedUrl !== url) {{
            console.log('XHR:', url, '->', proxiedUrl);
        }}
        return originalOpen.call(this, method, proxiedUrl, ...args);
    }};
    
    const originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {{
        if ((name === 'src' || name === 'href') && typeof value === 'string') {{
            const proxiedValue = proxyUrl(value);
            return originalSetAttribute.call(this, name, proxiedValue);
        }}
        return originalSetAttribute.call(this, name, value);
    }};
    
    console.log('Debug proxy enabled');
    console.log('=============================');
}})();
</script>
"""
                        
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
                        
                        set_cookie_headers = response.headers.get_all('Set-Cookie')
                        if set_cookie_headers:
                            return {
                                'statusCode': response.status,
                                'headers': response_headers,
                                'multiValueHeaders': {'Set-Cookie': set_cookie_headers},
                                'body': body
                            }
                        
                        return {
                            'statusCode': response.status,
                            'headers': response_headers,
                            'body': body
                        }
                    except Exception as e:
                        print(f"HTML processing error: {e}")
                        # Fall through to return raw content
                
                # CSS content
                if 'text/css' in content_type and is_text:
                    try:
                        def rewrite_css_url(match):
                            url = match.group(1).strip('\'"')
                            if url.startswith(('data:', '#')):
                                return match.group(0)
                            
                            # Use final_url for base (handles redirects)
                            parsed_final = urllib.parse.urlparse(final_url)
                            if url.startswith('//'):
                                url = f"{parsed_final.scheme}:{url}"
                            elif url.startswith('/'):
                                url = f"{parsed_final.scheme}://{parsed_final.netloc}{url}"
                            elif not url.startswith('http'):
                                url = urllib.parse.urljoin(final_url, url)
                            
                            proxy_url = f"{proxy_base_url}/debug?url={urllib.parse.quote(url, safe='')}&inline=true"
                            return f'url("{proxy_url}")'
                        
                        body = re.sub(r'url\(([^)]+)\)', rewrite_css_url, body)
                    except Exception as e:
                        print(f"CSS processing error: {e}")
                    
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
                
                # Binary content
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
                
                # Other text content
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
            
            # Non-inline mode: JSON debug response
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
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
            
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
        error_response = {
            'error': str(e),
            'error_type': type(e).__name__,
            'success': False,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
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
        
