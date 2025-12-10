import json
import urllib.parse
import urllib.request
import ssl
import socket
import re
import base64
from datetime import datetime

def rewrite_urls(html_content, original_url, proxy_base_url):
    """
    Rewrite all URLs in HTML to go through the proxy
    """
    parsed_original = urllib.parse.urlparse(original_url)
    base_url = parsed_original.scheme + '://' + parsed_original.netloc
    
    # Function to convert URL to proxied version
    def to_proxy_url(url):
        if not url or url.startswith('data:') or url.startswith('javascript:') or url.startswith('#'):
            return url
        
        # Make absolute
        if url.startswith('//'):
            url = parsed_original.scheme + ':' + url
        elif url.startswith('/'):
            url = base_url + url
        elif not url.startswith('http'):
            # Relative URL
            url = urllib.parse.urljoin(original_url, url)
        
        # Convert to proxy URL - always use /debug path
        return proxy_base_url + '/debug?site=' + urllib.parse.quote(url, safe='') + '&inline=true'
    
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
    """
    
    # Parse query parameters
    query_params = event.get('queryStringParameters', {})
    if not query_params or 'site' not in query_params:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Missing required parameter: site',
                'usage': 'Add ?site=example.com to the URL'
            })
        }
    
    target_site = query_params['site']
    inline_mode = query_params.get('inline', '').lower() in ['true', '1', 'yes']
    trace_mode = query_params.get('trace', '').lower() in ['true', '1', 'yes']
    
    # Always use api.tlsdebug.com as proxy base URL
    proxy_base_url = 'https://api.tlsdebug.com'
    
    # Clean up the site URL
    if not target_site.startswith('http'):
        target_site = 'https://' + target_site
    
    try:
        parsed_url = urllib.parse.urlparse(target_site)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        path = parsed_url.path or '/'
        
        # Prepare the request
        request_url = target_site if parsed_url.path else target_site + '/'
        
        # Create request
        req = urllib.request.Request(request_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
        req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8')
        req.add_header('Accept-Language', 'en-US,en;q=0.9')
        req.add_header('Accept-Encoding', 'gzip, deflate, br')
        req.add_header('Referer', parsed_url.scheme + '://' + parsed_url.netloc + '/')
        
        # Capture request details
        request_details = {
            'method': 'GET',
            'url': request_url,
            'hostname': hostname,
            'port': port,
            'path': path,
            'headers': dict(req.headers),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Log trace if enabled
        trace_log = []
        if trace_mode:
            trace_log.append({
                'event': 'request_start',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'url': request_url,
                'method': 'GET',
                'headers': dict(req.headers)
            })
        
        # Create SSL context to capture certificate info
        ssl_context = ssl.create_default_context()
        
        # Start timing
        import time
        start_time = time.time()
        
        # Make the request
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Get certificate information
            cert = response.fp.raw._sock.getpeercert()
            cipher = response.fp.raw._sock.cipher()
            
            # Log trace if enabled
            if trace_mode:
                trace_log.append({
                    'event': 'response_received',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'status': response.status,
                    'status_text': response.reason,
                    'headers': dict(response.headers),
                    'duration_ms': duration_ms
                })
            
            content_type = response.headers.get('Content-Type', 'text/html')
            
            # Read response body (limit to 100KB for HTML, 1MB for other)
            if inline_mode:
                # For inline mode, read more data and handle different content types
                if 'text/html' in content_type:
                    body = response.read(102400).decode('utf-8', errors='replace')
                elif 'text/css' in content_type or 'javascript' in content_type or 'text/' in content_type:
                    body = response.read(1048576).decode('utf-8', errors='replace')
                else:
                    # Binary content (images, fonts, etc.) - return as-is
                    body = response.read(1048576)
                    return {
                        'statusCode': response.status,
                        'headers': {
                            'Content-Type': content_type,
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                            'Access-Control-Allow-Headers': '*',
                        },
                        'body': base64.b64encode(body).decode('utf-8'),
                        'isBase64Encoded': True
                    }
            else:
                body = response.read(102400).decode('utf-8', errors='replace')
            
            # If inline mode, return the HTML directly
            if inline_mode and 'text/html' in content_type:
                # Rewrite all URLs to go through proxy
                body = rewrite_urls(body, request_url, proxy_base_url)
                
                # Add VERY early stage interceptor - must run before ANYTHING else
                early_interceptor = '''<script>
(function() {{
    // Store original values IMMEDIATELY
    var ORIGINAL_URL = "{orig_url}";
    var PROXY_BASE = "{proxy_base}";
    var parsed = new URL(ORIGINAL_URL);
    var ORIGINAL_ORIGIN = parsed.protocol + "//" + parsed.hostname;
    
    // Override document.write to catch any inline writes
    var originalWrite = document.write;
    document.write = function(html) {{
        // Don't proxy yet - let HTML load
        return originalWrite.call(document, html);
    }};
    
    // Override setAttribute to catch dynamic attribute changes
    var originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {{
        if ((name === 'src' || name === 'href') && typeof value === 'string') {{
            if (!value.startsWith('data:') && !value.startsWith('javascript:') && !value.startsWith('#') && !value.startsWith('blob:') && !value.includes('/debug?site=')) {{
                var absolute;
                if (value.startsWith('//')) {{
                    absolute = parsed.protocol + value;
                }} else if (value.startsWith('/')) {{
                    absolute = ORIGINAL_ORIGIN + value;
                }} else if (value.startsWith('http')) {{
                    absolute = value;
                }} else {{
                    try {{
                        absolute = new URL(value, ORIGINAL_URL).href;
                    }} catch(e) {{
                        absolute = value;
                    }}
                }}
                value = PROXY_BASE + '/debug?site=' + encodeURIComponent(absolute) + '&inline=true';
                console.log('setAttribute intercepted:', name, '->', value.substring(0, 100));
            }}
        }}
        return originalSetAttribute.call(this, name, value);
    }};
    
    // Override .src and .href property setters
    function wrapProperty(proto, prop) {{
        var desc = Object.getOwnPropertyDescriptor(proto, prop);
        if (!desc || !desc.set) return;
        
        var originalSet = desc.set;
        Object.defineProperty(proto, prop, {{
            set: function(value) {{
                if (typeof value === 'string' && !value.startsWith('data:') && !value.startsWith('javascript:') && !value.startsWith('#') && !value.startsWith('blob:') && !value.includes('/debug?site=')) {{
                    var absolute;
                    if (value.startsWith('//')) {{
                        absolute = parsed.protocol + value;
                    }} else if (value.startsWith('/')) {{
                        absolute = ORIGINAL_ORIGIN + value;
                    }} else if (value.startsWith('http')) {{
                        absolute = value;
                    }} else {{
                        try {{
                            absolute = new URL(value, ORIGINAL_URL).href;
                        }} catch(e) {{
                            absolute = value;
                        }}
                    }}
                    value = PROXY_BASE + '/debug?site=' + encodeURIComponent(absolute) + '&inline=true';
                    console.log('Property', prop, 'set:', value.substring(0, 100));
                }}
                return originalSet.call(this, value);
            }},
            get: desc.get,
            enumerable: desc.enumerable,
            configurable: desc.configurable
        }});
    }}
    
    // Wrap properties on various element types
    try {{
        wrapProperty(HTMLImageElement.prototype, 'src');
        wrapProperty(HTMLScriptElement.prototype, 'src');
        wrapProperty(HTMLIFrameElement.prototype, 'src');
        wrapProperty(HTMLSourceElement.prototype, 'src');
        wrapProperty(HTMLEmbedElement.prototype, 'src');
        wrapProperty(HTMLAnchorElement.prototype, 'href');
        wrapProperty(HTMLLinkElement.prototype, 'href');
    }} catch(e) {{
        console.error('Error wrapping properties:', e);
    }}
    
    console.log('Early interception initialized for:', ORIGINAL_URL);
}})();
</script>
'''.format(orig_url=request_url, proxy_base=proxy_base_url)
                
                # Add debug console logging script and URL interceptor
                trace_info = ""
                if trace_mode:
                    trace_info = '''
    // TRACE MODE ENABLED
    console.log("\\n=== TRACE LOG ===");
    console.log("Request Duration:", {duration_ms}, "ms");
    console.log("Response Status:", {status}, "{status_text}");
    console.log("Response Headers:", {response_headers});
    console.log("Content Type:", "{content_type}");
    console.log("Body Size:", {body_size}, "bytes");
    console.log("=================\\n");
'''.format(
                        duration_ms=duration_ms,
                        status=response.status,
                        status_text=response.reason,
                        response_headers=json.dumps(dict(response.headers)),
                        content_type=content_type,
                        body_size=len(body)
                    )
                
                debug_script = '''<script>
(function() {{
    var ORIGINAL_URL = "{orig_url}";
    var PROXY_BASE = "{proxy_base}";
    var parsed = new URL(ORIGINAL_URL);
    var ORIGINAL_ORIGIN = parsed.protocol + "//" + parsed.hostname;
    
    console.log("=== TLS Debug Inline Mode ===");
    console.log("Original URL:", ORIGINAL_URL);
    console.log("Original Origin:", ORIGINAL_ORIGIN);
    console.log("All resources are being proxied");
    console.log("Proxy URL:", window.location.href);
    {trace_info}
    
    // Function to convert URL to proxied version
    function proxyUrl(url) {{
        if (!url || url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('#') || url.startsWith('blob:')) {{
            return url;
        }}
        
        // Already proxied?
        if (url.includes('/debug?site=')) {{
            return url;
        }}
        
        // Make absolute
        var absoluteUrl;
        try {{
            if (url.startsWith('//')) {{
                absoluteUrl = parsed.protocol + url;
            }} else if (url.startsWith('/')) {{
                absoluteUrl = ORIGINAL_ORIGIN + url;
            }} else if (url.startsWith('http')) {{
                absoluteUrl = url;
            }} else {{
                absoluteUrl = new URL(url, ORIGINAL_URL).href;
            }}
        }} catch(e) {{
            return url;
        }}
        
        // Proxy it
        return PROXY_BASE + '/debug?site=' + encodeURIComponent(absoluteUrl) + '&inline=true';
    }}
    
    // Intercept all clicks
    document.addEventListener('click', function(e) {{
        var target = e.target;
        while (target && target.tagName !== 'A') {{
            target = target.parentElement;
        }}
        if (target && target.href) {{
            var original = target.getAttribute('href');
            if (original && !original.startsWith('#') && !original.startsWith('javascript:')) {{
                e.preventDefault();
                var proxied = proxyUrl(original);
                console.log("Click intercepted:", original, "->", proxied);
                window.location.href = proxied;
            }}
        }}
    }}, true);
    
    // Intercept dynamic script/img creation
    var originalCreateElement = document.createElement;
    document.createElement = function(tagName) {{
        var element = originalCreateElement.call(document, tagName);
        if (tagName.toLowerCase() === 'script' || tagName.toLowerCase() === 'img') {{
            var srcDescriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'src') || 
                               Object.getOwnPropertyDescriptor(Element.prototype, 'src');
            if (srcDescriptor && srcDescriptor.set) {{
                var originalSetter = srcDescriptor.set;
                Object.defineProperty(element, 'src', {{
                    set: function(value) {{
                        var proxied = proxyUrl(value);
                        console.log("Dynamic src set:", value, "->", proxied);
                        originalSetter.call(this, proxied);
                    }},
                    get: srcDescriptor.get
                }});
            }}
        }}
        return element;
    }};
    
    // Intercept fetch API
    var originalFetch = window.fetch;
    window.fetch = function(url, options) {{
        var proxied = proxyUrl(url);
        console.log("Fetch intercepted:", url, "->", proxied);
        return originalFetch.call(this, proxied, options);
    }};
    
    // Intercept XMLHttpRequest
    var originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {{
        var proxied = proxyUrl(url);
        console.log("XHR intercepted:", url, "->", proxied);
        return originalOpen.apply(this, [method, proxied].concat(Array.prototype.slice.call(arguments, 2)));
    }};
    
    window.addEventListener('load', function() {{
        console.log("Page fully loaded");
        console.log("Scripts:", document.scripts.length);
        console.log("Stylesheets:", document.styleSheets.length);
        console.log("Images:", document.images.length);
    }});
    
    window.addEventListener('error', function(e) {{
        console.error("Resource failed to load:", e.target.src || e.target.href || e.message);
    }}, true);
    
    window.addEventListener('securitypolicyviolation', function(e) {{
        console.error("Security Policy Violation:", e.violatedDirective, e.blockedURI);
    }});
    
    console.log("Debug logging and URL interception enabled");
    console.log("=============================");
}})();
</script>
'''.format(orig_url=request_url, proxy_base=proxy_base_url, trace_info=trace_info)
                
                # Insert early interceptor and debug script after <head> tag
                if '<head>' in body.lower():
                    body_lower = body.lower()
                    head_pos = body_lower.find('<head>') + 6
                    body = body[:head_pos] + early_interceptor + debug_script + body[head_pos:]
                elif '<html>' in body.lower():
                    body_lower = body.lower()
                    html_pos = body_lower.find('<html>') + 6
                    body = body[:html_pos] + '<head>' + early_interceptor + debug_script + '</head>' + body[html_pos:]
                else:
                    body = early_interceptor + debug_script + body
                
                return {
                    'statusCode': response.status,
                    'headers': {
                        'Content-Type': response.headers.get('Content-Type', 'text/html'),
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                        'Access-Control-Allow-Headers': '*',
                        'Access-Control-Expose-Headers': '*',
                        'Access-Control-Allow-Credentials': 'true',
                        'X-Content-Type-Options': 'nosniff',
                        'X-Frame-Options': 'ALLOWALL',
                        'Content-Security-Policy': "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; img-src * data: blob:; font-src * data:; connect-src *; frame-src *;"
                    },
                    'body': body
                }
            
            # If inline mode and CSS, rewrite URLs in CSS
            if inline_mode and 'text/css' in content_type:
                # Rewrite url() in CSS
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
                    # Proxy it - always use /debug path
                    proxy_url = proxy_base_url + '/debug?site=' + urllib.parse.quote(url, safe='') + '&inline=true'
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
            
            # If inline mode and JS/other text, return as-is
            if inline_mode:
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
            
            # Capture response details
            response_details = {
                'status_code': response.status,
                'status_message': response.reason,
                'headers': dict(response.headers),
                'body_preview': body[:1000] if len(body) > 1000 else body,
                'body_size': len(body),
                'truncated': len(body) > 1000,
                'duration_ms': duration_ms
            }
            
            # Add final trace log
            if trace_mode:
                trace_log.append({
                    'event': 'processing_complete',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'body_size': len(body),
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
            
            # Add trace log if trace mode enabled
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
        # If inline mode, try to return error page HTML if available
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
        
        # Add error to trace log
        if trace_mode:
            trace_log.append({
                'event': 'error',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'error_type': 'HTTPError',
                'status_code': e.code,
                'error_message': str(e.reason)
            })
        
        error_response = {
            'request': request_details,
            'response': {
                'status_code': e.code,
                'status_message': e.reason,
                'headers': dict(e.headers),
                'error': str(e)
            },
            'success': False
        }
        
        if trace_mode:
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
        
        # Add trace log if it exists and trace mode was enabled
        if 'trace_log' in locals() and trace_mode:
            trace_log.append({
                'event': 'error',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'error_type': type(e).__name__,
                'error_message': str(e)
            })
            error_response['trace'] = trace_log
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(error_response, indent=2)
        }
