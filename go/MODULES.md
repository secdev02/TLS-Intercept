# TLS Proxy Logging Modules

## Overview

The TLS Proxy supports an extensible logging module system that allows you to:
- Filter which traffic gets logged
- Modify requests before they reach the server
- Modify responses before they reach the client
- Create custom traffic analysis and manipulation logic

## Module Interface

All modules must implement the `LogModule` interface:

```go
type LogModule interface {
    Name() string                           // Module identifier
    ShouldLog(req *http.Request) bool      // Return true to log this request
    ProcessRequest(req *http.Request) error    // Modify request (runs on all requests)
    ProcessResponse(resp *http.Response) error // Modify response (runs on all responses)
}
```

## Built-in Modules

### 1. AllTrafficModule (Default)
Logs all traffic without filtering.

**Use case:** General debugging, full traffic capture

**Configuration:**
```go
RegisterModule(&AllTrafficModule{})
```

### 2. OAuthModule
Only logs OAuth and authentication flows.

**Detects:**
- URLs containing: /oauth, /auth, /login, /token, /authorize, /callback
- Requests with Authorization headers
- OAuth parameters: access_token, refresh_token, client_id, client_secret

**Use case:** Debugging authentication issues, token flows

**Configuration:**
```go
RegisterModule(&OAuthModule{})
```

**Example output:**
```
[OAuth] Detected OAuth flow: https://accounts.google.com/oauth/authorize
[OAuth] Detected Authorization header
```

### 3. DomainFilterModule
Only logs traffic to specific domains.

**Use case:** Focus on specific APIs or services

**Configuration:**
```go
RegisterModule(&DomainFilterModule{
    Domains: []string{"example.com", "api.github.com"},
})
```

**Example:** Only log traffic to example.com and api.github.com

### 4. PathFilterModule
Only logs requests to specific URL paths.

**Use case:** Focus on specific API endpoints

**Configuration:**
```go
RegisterModule(&PathFilterModule{
    Paths: []string{"/api/", "/v1/users"},
})
```

**Example:** Only log requests to /api/ and /v1/users paths

### 5. RequestModifierModule
Adds or removes headers from requests before forwarding.

**Use case:** Testing how servers respond to different headers, debugging, adding custom authentication

**Configuration:**
```go
RegisterModule(&RequestModifierModule{
    AddHeaders: map[string]string{
        "X-Custom-Header": "value",
        "X-Debug-Mode": "true",
    },
    RemoveHeaders: []string{"User-Agent", "Cookie"},
})
```

**Example output:**
```
[RequestModifier] Added header: X-Custom-Header: value
[RequestModifier] Removed header: User-Agent
```

### 6. ResponseModifierModule
Adds or removes headers from responses before returning to client.

**Use case:** Testing client behavior with different response headers, removing security headers

**Configuration:**
```go
RegisterModule(&ResponseModifierModule{
    AddHeaders: map[string]string{
        "X-Proxy-Modified": "true",
        "Access-Control-Allow-Origin": "*",
    },
    RemoveHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
})
```

## Creating Custom Modules

### Step 1: Define Your Module Struct

```go
type MyCustomModule struct {
    // Add any configuration fields you need
    TargetDomain string
    Counter      int
}
```

### Step 2: Implement the Interface

```go
func (m *MyCustomModule) Name() string {
    return "MyCustomModule"
}

func (m *MyCustomModule) ShouldLog(req *http.Request) bool {
    // Return true if you want this request logged
    return strings.Contains(req.URL.Host, m.TargetDomain)
}

func (m *MyCustomModule) ProcessRequest(req *http.Request) error {
    // Modify the request here
    m.Counter++
    req.Header.Set("X-Request-Count", fmt.Sprintf("%d", m.Counter))
    log.Printf("[MyCustomModule] Processing request #%d", m.Counter)
    return nil
}

func (m *MyCustomModule) ProcessResponse(resp *http.Response) error {
    // Modify the response here
    resp.Header.Set("X-Processed-By", "MyCustomModule")
    return nil
}
```

### Step 3: Register Your Module

Add to `initializeModules()` function in tlsproxy.go:

```go
func initializeModules() {
    RegisterModule(&MyCustomModule{
        TargetDomain: "api.example.com",
        Counter:      0,
    })
}
```

## Advanced Examples

### Example 1: API Rate Limiting Detector

```go
type RateLimitModule struct {
    Threshold int
    Count     map[string]int
    mu        sync.Mutex
}

func (m *RateLimitModule) Name() string {
    return "RateLimitDetector"
}

func (m *RateLimitModule) ShouldLog(req *http.Request) bool {
    return true
}

func (m *RateLimitModule) ProcessRequest(req *http.Request) error {
    return nil
}

func (m *RateLimitModule) ProcessResponse(resp *http.Response) error {
    if resp.StatusCode == 429 {
        log.Printf("[RateLimit] Rate limit hit on: %s", resp.Request.URL)
    }
    
    if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
        log.Printf("[RateLimit] Remaining: %s", remaining)
    }
    
    return nil
}
```

### Example 2: JSON Response Logger

```go
type JSONResponseModule struct{}

func (m *JSONResponseModule) Name() string {
    return "JSONResponse"
}

func (m *JSONResponseModule) ShouldLog(req *http.Request) bool {
    return true
}

func (m *JSONResponseModule) ProcessRequest(req *http.Request) error {
    return nil
}

func (m *JSONResponseModule) ProcessResponse(resp *http.Response) error {
    contentType := resp.Header.Get("Content-Type")
    
    if strings.Contains(contentType, "application/json") {
        body, err := io.ReadAll(resp.Body)
        if err == nil {
            resp.Body = io.NopCloser(bytes.NewBuffer(body))
            
            // Pretty print JSON
            var prettyJSON bytes.Buffer
            if err := json.Indent(&prettyJSON, body, "", "  "); err == nil {
                log.Printf("[JSONResponse] Response body:\n%s", prettyJSON.String())
            }
        }
    }
    
    return nil
}
```

### Example 3: Security Header Analyzer

```go
type SecurityHeaderModule struct{}

func (m *SecurityHeaderModule) Name() string {
    return "SecurityHeaders"
}

func (m *SecurityHeaderModule) ShouldLog(req *http.Request) bool {
    return true
}

func (m *SecurityHeaderModule) ProcessRequest(req *http.Request) error {
    return nil
}

func (m *SecurityHeaderModule) ProcessResponse(resp *http.Response) error {
    securityHeaders := []string{
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
    }
    
    missing := []string{}
    for _, header := range securityHeaders {
        if resp.Header.Get(header) == "" {
            missing = append(missing, header)
        }
    }
    
    if len(missing) > 0 {
        log.Printf("[SecurityHeaders] Missing from %s: %s", 
            resp.Request.URL.Host, 
            strings.Join(missing, ", "))
    }
    
    return nil
}
```

## Module Execution Flow

1. **Request Phase:**
   ```
   Client Request → All modules.ProcessRequest() → ShouldLog() check → Log if true → Forward to server
   ```

2. **Response Phase:**
   ```
   Server Response → All modules.ProcessResponse() → Return to client
   ```

3. **Key Points:**
   - `ProcessRequest()` and `ProcessResponse()` run for ALL requests/responses
   - `ShouldLog()` only controls whether the request gets logged to console/file
   - Modules are executed in registration order
   - Errors in one module don't stop other modules from executing

## Module Combinations

You can combine multiple modules for powerful workflows:

### Example: OAuth + Domain Filter
```go
func initializeModules() {
    // Only log OAuth flows from specific domains
    RegisterModule(&OAuthModule{})
    RegisterModule(&DomainFilterModule{
        Domains: []string{"accounts.google.com", "login.microsoft.com"},
    })
}
```

Note: For traffic to be logged, at least one module must return `true` from `ShouldLog()`.

### Example: Modify + Filter + Log
```go
func initializeModules() {
    // Add debug headers to all requests
    RegisterModule(&RequestModifierModule{
        AddHeaders: map[string]string{"X-Debug": "true"},
    })
    
    // But only log API calls
    RegisterModule(&PathFilterModule{
        Paths: []string{"/api/"},
    })
    
    // And analyze security headers on responses
    RegisterModule(&SecurityHeaderModule{})
}
```

## Best Practices

1. **Module Naming:** Use descriptive names that indicate the module's purpose
2. **Error Handling:** Return errors from ProcessRequest/ProcessResponse but log them - don't panic
3. **Performance:** Keep ProcessRequest/ProcessResponse fast - they run on every request
4. **State Management:** Use mutexes if your module maintains state across requests
5. **Logging:** Prefix your module's log messages with [ModuleName] for clarity
6. **Testing:** Test modules with curl or browser before using in production

## Disabling Modules

Comment out the RegisterModule() call in `initializeModules()`:

```go
func initializeModules() {
    // RegisterModule(&OAuthModule{})  // Disabled
    RegisterModule(&AllTrafficModule{}) // Enabled
}
```

## Contributing Modules

To contribute a new module:

1. Create your module following the interface
2. Add it to the built-in modules section in tlsproxy.go
3. Document it in this file
4. Add usage examples
5. Test with various scenarios
6. Submit a pull request

## Troubleshooting

**Module not logging anything:**
- Check if `ShouldLog()` returns true for your traffic
- Verify the module is registered in `initializeModules()`
- Check for conflicting filter modules (all must return true)

**Request modifications not working:**
- Ensure `ProcessRequest()` runs before forwarding
- Check for errors in the console output
- Verify header names are correct (case-sensitive)

**Performance issues:**
- Profile your module's ProcessRequest/ProcessResponse functions
- Avoid expensive operations on every request
- Consider adding filtering logic in ShouldLog() first
