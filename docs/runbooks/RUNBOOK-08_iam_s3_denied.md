# SRE Runbook: IAM Policy / S3 AccessDenied (403)
**Fault Identifier**: `08_iam_s3_denied`  
**Classification**: Security & Authorization Subsystem  
**Default Severity**: SEV-2  

## 1. Symptoms & Initial Indicators
- API returns HTTP 403 Forbidden with XML body: `<Code>AccessDenied</Code><Message>Access Denied</Message>`.
- Application error: `botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the GetObject operation`.
- CloudTrail logs `eventSource: s3.amazonaws.com`, `errorCode: AccessDenied`.

## 2. Fast Diagnostic Commands
```bash
# 1. Verify caller identity and assumed IAM role ARN
aws sts get-caller-identity

# 2. Test S3 bucket accessibility directly using assumed credentials
aws s3 ls s3://triageforge-assets/

# 3. Simulate IAM policy evaluation using IAM Policy Simulator
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::123456789012:role/TriageForgeAppRole" \
  --action-names "s3:GetObject" "s3:PutObject" \
  --resource-arns "arn:aws:s3:::triageforge-assets/*"
```

## 3. Immediate Mitigation Steps
1. Attach required S3 permissions to the execution role:
   ```json
   {
       "Effect": "Allow",
       "Action": [
           "s3:GetObject",
           "s3:PutObject"
       ],
       "Resource": "arn:aws:s3:::triageforge-assets/*"
   }
   ```
2. Verify S3 Bucket Policy does not contain an explicit `Deny` override.

## 4. Long-Term Remediation
- Follow Principle of Least Privilege: scope IAM policies down to exact bucket ARNs and prefixes.
- Enforce IAM policy unit testing via `awspec` or Terraform validation before staging promotion.
