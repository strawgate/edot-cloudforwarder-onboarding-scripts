# EDOT Cloud Forwarder - AWS Log Source Discovery Tool

Discover AWS log sources and deploy [EDOT Cloud Forwarder](https://www.elastic.co/guide/en/observability/current/edot-cloud-forwarder.html) with a single command.

## Quick Start

Open [AWS CloudShell](https://console.aws.amazon.com/cloudshell) and run:

```bash
curl -fsSL http://ela.st/onboard-ecf-aws | bash
```

That's it. The script installs the tool and launches an interactive wizard that:

1. Discovers your VPC Flow Logs, ELB Access Logs, CloudTrail trails, and WAF logs
2. Lets you select which sources to onboard
3. Deploys EDOT Cloud Forwarder via CloudFormation

> **Why CloudShell?** It has AWS credentials pre-configured and all required tools installed. No setup needed.

## Supported Log Sources

| Log Type | Source | Destination |
|----------|--------|-------------|
| VPC Flow Logs | VPCs, Subnets, ENIs | S3 Bucket |
| ELB Access Logs | ALB, NLB, Classic ELB | S3 Bucket |
| CloudTrail | Trails (single/multi-region/organization) | S3 Bucket |
| AWS WAF | Web ACLs (Regional and CloudFront) | S3 Bucket |

## What You'll Need

- **Elastic Cloud OTLP endpoint** and **API key** - find these in Kibana under Management -> Fleet -> Agent Policies -> OTLP Endpoint

---

## Alternative Installation Methods

### Local Installation with uv

If you prefer to run locally instead of CloudShell:

```bash
# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and run
git clone https://github.com/strawgate/edot-cloudforwarder-onboarding-scripts.git
cd edot-cloudforwarder-onboarding-scripts
aws configure  # if not already configured
uv run edot-discover
```

### Manual Script Review

If you want to review the install script before running:

```bash
# Download and inspect
curl -fsSL https://raw.githubusercontent.com/strawgate/edot-cloudforwarder-onboarding-scripts/main/install.sh -o install.sh
cat install.sh

# Run after review
bash install.sh
```

---

## Detailed Usage

### Interactive Workflow

```bash
uv run edot-discover
```

The tool walks you through:

1. **Credential verification** - displays your AWS account and caller identity
2. **Region selection** - pick from all enabled regions in your account
3. **Discovery** - finds all S3-backed log sources
4. **Source selection** - multi-select interface (all sources pre-selected by default)
5. **Elastic configuration** - enter your OTLP endpoint and API key
6. **Dry run preview** - review CloudFormation commands (API key redacted)
7. **Deployment** - optionally execute the deployments

### Example Session

```text
EDOT Cloud Forwarder
AWS Log Source Discovery & Onboarding Tool

AWS Account: 123456789012
Caller ARN: arn:aws:iam::123456789012:user/admin

? Select AWS region to scan: us-east-1 (current)

Scanning region us-east-1 for log sources...

                    Discovered 3 Log Source(s)
╭────────────────┬─────────────┬──────────────────────┬────────────────╮
│ Type           │ ID          │ S3 Destination       │ Status         │
├────────────────┼─────────────┼──────────────────────┼────────────────┤
│ VPC Flow Logs  │ fl-abc123   │ s3://my-vpc-logs/... │ Not configured │
│ ALB Access Log │ my-alb      │ s3://my-alb-logs/alb │ Not configured │
│ CloudTrail     │ main-trail  │ s3://cloudtrail-logs │ Not configured │
╰────────────────┴─────────────┴──────────────────────┴────────────────╯

? Select log sources to onboard: (Space to toggle, Enter to confirm)
 > [X] fl-abc123 (VPC Flow Logs) -> arn:aws:s3:::my-vpc-logs
   [X] my-alb (ALB Access Logs) -> arn:aws:s3:::my-alb-logs
   [X] main-trail (CloudTrail) -> arn:aws:s3:::cloudtrail-logs

? OTLP Endpoint URL: https://my-deployment.apm.us-east-1.aws.cloud.es.io:443
? Elastic API Key: ********

╭──────────────────── Dry Run Preview ────────────────────╮
│ Review the CloudFormation commands below...             │
│ Commands are formatted for copy/paste.                  │
│ Note: API key is shown as <REDACTED> - substitute yours │
╰─────────────────────────────────────────────────────────╯

# Stack 1 (us-east-1): VPC Flow Logs
# Bucket: arn:aws:s3:::my-vpc-logs
aws cloudformation create-stack --stack-name edot-cf-vpcflow-my-vpc-logs ...

# Stack 2 (us-east-1): ELB Access Logs
# Bucket: arn:aws:s3:::my-alb-logs
aws cloudformation create-stack --stack-name edot-cf-elbaccess-my-alb-logs ...

? Execute 2 CloudFormation deployment(s)? Yes

All 2 stack(s) initiated successfully!
```

---

## Reference

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeFlowLogs",
    "ec2:DescribeRegions",
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeLoadBalancerAttributes",
    "cloudtrail:DescribeTrails",
    "wafv2:ListWebACLs",
    "wafv2:GetLoggingConfiguration",
    "s3:GetBucketLocation",
    "cloudformation:ListStacks",
    "cloudformation:DescribeStacks",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

### Architecture Notes

- **One stack per bucket+log type** - EDOT Cloud Forwarder requires dedicated processing per log type
- **Same region deployment** - CloudFormation stack deploys in the same region as the S3 bucket
- **Lambda-based** - each stack deploys a Lambda triggered by S3 events
- **Idempotent** - stack names are deterministic, so re-running is safe

### CloudFormation Template

The tool uses Elastic's published template:

```
https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml
```

Also available via AWS Serverless Application Repository as `edot-cloud-forwarder-s3-logs`.

---

## Troubleshooting

### No sources found

- Verify you have log sources configured to write to S3 (VPC Flow Logs, ELB Access Logs, CloudTrail, or WAF)
- Check you're scanning the correct region
- Ensure your IAM permissions include the required actions listed above

### Permission denied errors

Your AWS credentials need the permissions listed in [Required IAM Permissions](#required-iam-permissions).

### CloudFormation deployment fails

- Verify the S3 bucket exists and is in the same region as the stack
- Check your Elastic API key is valid
- Ensure `CAPABILITY_NAMED_IAM` is accepted (handled automatically by the tool)

---

## Development

See [DEVELOPING.md](DEVELOPING.md) for development setup and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

Apache 2.0
