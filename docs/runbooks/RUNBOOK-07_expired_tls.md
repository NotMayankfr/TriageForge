# SRE Runbook: TLS Certificate Expiry / Mismatch
**Fault Identifier**: `07_expired_tls`  
**Classification**: Security Subsystem  
**Default Severity**: SEV-2  

## 1. Symptoms & Initial Indicators
- Browsers display red security warnings: `NET::ERR_CERT_DATE_INVALID` or `SSL_ERROR_EXPIRED_CERT_ALERT`.
- `curl` fails with: `curl: (60) SSL certificate problem: certificate has expired`.
- Python clients throw: `ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired`.

## 2. Fast Diagnostic Commands
```bash
# 1. Inspect peer certificate dates, subject, issuer, and SANs
openssl s_client -connect localhost:443 -servername triageforge.local -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer -ext subjectAltName

# 2. Check remaining days on local cert file
openssl x509 -in /etc/nginx/certs/active.crt -noout -enddate -checkend 86400

# 3. Test curl with verbose SSL handshake debugging
curl -vvv https://localhost:443 --cacert /path/to/ca.crt
```

## 3. Immediate Mitigation Steps
1. **Rotate to renewed certificate**:
   ```bash
   cp /etc/nginx/certs/valid.crt /etc/nginx/certs/active.crt
   cp /etc/nginx/certs/valid.key /etc/nginx/certs/active.key
   nginx -s reload
   ```
2. **If using Certbot / Let's Encrypt**:
   ```bash
   certbot renew --force-renewal && systemctl reload nginx
   ```

## 4. Long-Term Remediation
- Use AWS Certificate Manager (ACM) attached to ALB/CloudFront for automated zero-touch renewal.
- Setup Prometheus / Datadog TLS certificate expiration alerts when expiration is < 30 days away.
