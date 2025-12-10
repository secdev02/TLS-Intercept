#  TLS Debug

A serverless HTTPS debugging tool that acts as a reverse proxy to inspect TLS/SSL connections, certificates, and HTTP requests/responses.

## Features

-  **TLS/SSL Analysis**: View certificate details, cipher suites, and protocol versions
-  **Request Inspection**: See all request headers and parameters
-  **Response Inspection**: View response headers, status codes, and body preview
-  **Serverless**: Built on AWS Lambda for automatic scaling and pay-per-use pricing
-  **Beautiful UI**: Clean, modern single-page interface
-  **Fast**: Typically responds in < 2 seconds

## Live Demo

Visit: `https://www.tlsdebug.com/?site=example.com`

## Use Cases

- Debug TLS/SSL certificate issues
- Inspect HTTP headers from servers
- Verify cipher suites and protocols
- Test API endpoints
- Troubleshoot HTTPS connectivity
- Learn about TLS handshakes

## Quick Start

### Prerequisites

Choose one deployment method:

**Option 1: Serverless Framework** (Easiest)
```bash
npm install -g serverless
```

**Option 2: AWS SAM**
```bash
brew install aws-sam-cli  # or equivalent for your OS
```

**Option 3: AWS CLI** (Manual)
```bash
# AWS CLI already configured
```

### Deploy Backend

#### Using Serverless Framework (Recommended)

```bash
# Install dependencies
npm install -g serverless

# Deploy
serverless deploy

# Note the API endpoint URL from the output
```

#### Using AWS SAM

```bash
# Build and deploy
sam build
sam deploy --guided

# Follow prompts and note the API URL
```

#### Manual with AWS CLI

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

### Deploy Frontend

1. **Update API endpoint** in `index.html`:
   ```javascript
   const API_ENDPOINT = 'https://YOUR_API_ID.execute-api.REGION.amazonaws.com/debug';
   ```

2. **Upload to S3:**
   ```bash
   aws s3 cp index.html s3://tlsdebug.com/ --acl public-read
   ```

3. **Configure DNS** to point to your S3 bucket or CloudFront distribution

## Architecture

```
User Browser
    ↓
S3/CloudFront (Static HTML)
    ↓
API Gateway
    ↓
Lambda Function (Python)
    ↓
Target HTTPS Site
```

### Components

- **Frontend**: Single-page HTML/CSS/JavaScript app
- **Backend**: Python Lambda function
- **API**: AWS API Gateway (HTTP API)
- **Hosting**: S3 + CloudFront (or S3 static website)

## API Usage

### Endpoint

```
GET /debug?site={domain}
```

### Parameters

- `site` (required): Domain or full URL to debug
  - Examples: `example.com`, `https://api.github.com`

### Response Format

```json
{
  "request": {
    "method": "GET",
    "url": "https://example.com/",
    "hostname": "example.com",
    "port": 443,
    "path": "/",
    "headers": {...},
    "timestamp": "2024-01-01T12:00:00Z"
  },
  "response": {
    "status_code": 200,
    "status_message": "OK",
    "headers": {...},
    "body_preview": "...",
    "body_size": 1256
  },
  "tls": {
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "bits": 256,
    "certificate": {
      "subject": {...},
      "issuer": {...},
      "not_before": "Jan 1 00:00:00 2024 GMT",
      "not_after": "Dec 31 23:59:59 2024 GMT",
      "san": [["DNS", "example.com"], ["DNS", "*.example.com"]]
    }
  },
  "success": true
}
```

## Examples

### Debug a website
```
https://tlsdebug.com/?site=github.com
```

### Check API endpoint
```
https://tlsdebug.com/?site=api.github.com
```

### Test with different domains
```
https://tlsdebug.com/?site=google.com
https://tlsdebug.com/?site=amazon.com
https://tlsdebug.com/?site=cloudflare.com
```

## Cost

For typical usage (< 100K requests/month):
- **Lambda**: ~$0.20
- **API Gateway**: ~$0.10
- **S3**: ~$0.05
- **CloudFront**: ~$0.10

**Total: < $1/month**

## Limitations

- **Timeout**: 30 seconds per request
- **Body size**: Response bodies limited to 100KB
- **Rate limit**: Can be configured in API Gateway (default: unlimited)
- **No authentication**: Currently public (add API keys if needed)

## Security Features

- CORS enabled for browser access
- Input validation on domain parameter
- No sensitive data stored
- Automatic SSL certificate verification
- Request timeout protection

## Development

### Local Testing

Test the Lambda function locally:

```python
python lambda_function.py
```

Or use SAM:

```bash
sam local start-api
curl "http://localhost:3000/debug?site=example.com"
```

### Testing API Directly

```bash
curl "https://YOUR_API_URL/debug?site=example.com" | jq
```

## Monitoring

View Lambda logs:
```bash
aws logs tail /aws/lambda/tls-debug-proxy --follow
```

CloudWatch metrics:
- Lambda invocations
- Lambda errors
- Lambda duration
- API Gateway 4XX/5XX errors

## Customization

### Add Authentication

Add API key requirement in `serverless.yml`:

```yaml
functions:
  debug:
    events:
      - httpApi:
          path: /debug
          method: get
          authorizer:
            type: api_key
```

### Add Rate Limiting

Configure throttling in API Gateway:

```yaml
provider:
  httpApi:
    throttle:
      rateLimit: 100
      burstLimit: 50
```

### Custom Domain

1. Register certificate in ACM
2. Configure custom domain in API Gateway
3. Update Route 53 DNS

## Troubleshooting

### CORS Errors
- Ensure Lambda returns `Access-Control-Allow-Origin: *` header
- Check API Gateway CORS configuration

### Timeout Errors
- Target site may be slow or unreachable
- Consider increasing Lambda timeout

### Certificate Errors
- Some sites may use client certificates
- Self-signed certificates will be rejected

### DNS Propagation
- Can take up to 48 hours
- Test with CloudFront URL first

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT License - feel free to use this for any purpose.

## Support

For issues or questions:


## Roadmap

- [ ] Add support for custom headers
- [ ] Show DNS resolution details
- [ ] Add HTTP/2 and HTTP/3 support
- [ ] Response time metrics
- [ ] Save/share debug sessions
- [ ] Compare multiple sites
- [ ] WebSocket support
- [ ] Authentication options

---

Built with ❤️ using AWS Lambda, API Gateway, and vanilla JavaScript
