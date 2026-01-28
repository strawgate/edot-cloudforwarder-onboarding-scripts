# EDOT Cloud Forwarder - AWS Log Source Discovery Tool

An interactive CLI tool that discovers AWS log sources and generates CloudFormation deployment commands for [EDOT Cloud Forwarder](https://www.elastic.co/guide/en/observability/current/edot-cloud-forwarder.html).

## Overview

EDOT Cloud Forwarder is Elastic's OpenTelemetry-native serverless log collector deployed as an AWS Lambda function. This tool helps you:

1. **Discover** VPC Flow Logs and ELB Access Logs writing to S3 buckets
2. **Select** which log sources to onboard via an interactive multi-select interface
3. **Generate** CloudFormation deployment commands for EDOT Cloud Forwarder

## Supported Log Sources

| Log Type | Source | Destination |
|----------|--------|-------------|
| VPC Flow Logs | VPCs, Subnets, ENIs | S3 Bucket |
| ELB Access Logs | ALB, NLB, Classic ELB | S3 Bucket |

## Requirements

- Python 3.8+
- AWS credentials with the following permissions:
  ```json
  {
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeFlowLogs",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }
  ```

## Quick Start (AWS CloudShell)

AWS CloudShell is the recommended environment - it has Python, pip, and pre-configured AWS credentials.

```bash
# Clone the repository
git clone https://github.com/elastic/edot-cloudforwarder-onboarding-scripts.git
cd edot-cloudforwarder-onboarding-scripts

# Install dependencies (persists in CloudShell's $HOME)
pip install --user -r requirements.txt

# Run the discovery tool
python discover.py
```

## Quick Start (Local)

```bash
# Clone the repository
git clone https://github.com/elastic/edot-cloudforwarder-onboarding-scripts.git
cd edot-cloudforwarder-onboarding-scripts

# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure

# Run the discovery tool
python discover.py
```

## Usage

### Interactive Mode

Simply run the script and follow the prompts:

```bash
python discover.py
```

The tool will:

1. Verify your AWS credentials and display your account info
2. Ask for the AWS region to scan
3. Discover all VPC Flow Logs and ELB Access Logs writing to S3
4. Display results in a formatted table
5. Present a multi-select interface (all sources pre-selected)
6. Ask for your Elastic Cloud OTLP endpoint and API key
7. Generate and display CloudFormation commands
8. Optionally execute the deployments

### Example Session

```
EDOT Cloud Forwarder
AWS Log Source Discovery & Onboarding Tool

AWS Account: 123456789012
Caller ARN: arn:aws:iam::123456789012:user/admin

? AWS Region to scan: us-east-1

Scanning region us-east-1 for log sources...

              Discovered 3 Log Source(s)
+----------------+-------------+------------+------------------------+
| Type           | ID          | Resource   | S3 Destination         |
+----------------+-------------+------------+------------------------+
| VPC Flow Logs  | fl-abc123   | vpc-xyz789 | arn:aws:s3:::my-vpc... |
| ALB Access Log | my-alb      | arn:aws... | s3://my-alb-logs/alb   |
| NLB Access Log | my-nlb      | arn:aws... | s3://my-nlb-logs/nlb   |
+----------------+-------------+------------+------------------------+

? Select log sources to onboard: (Use arrow keys, Space to toggle)
 > [X] fl-abc123 (vpc-xyz789) -> arn:aws:s3:::my-vpc-logs
   [X] my-alb (ALB Access Logs) -> arn:aws:s3:::my-alb-logs
   [X] my-nlb (NLB Access Logs) -> arn:aws:s3:::my-nlb-logs

? OTLP Endpoint URL: https://my-deployment.apm.us-east-1.aws.cloud.es.io:443
? Elastic API Key: ********

Dry Run Preview
[Commands displayed here...]

? Execute 2 CloudFormation deployment(s)? No

Deployment cancelled. Commands have been printed above - copy and run manually when ready.
```

## Elastic Cloud Configuration

To find your OTLP endpoint and API key:

1. Log in to [Elastic Cloud](https://cloud.elastic.co/)
2. Navigate to **Kibana** -> **Management** -> **Fleet**
3. Go to **Agent Policies** -> Select your policy
4. Find the **OTLP Endpoint** section

Or create a new API key in **Kibana** -> **Management** -> **API Keys**.

## Architecture Notes

- **One stack per log type**: EDOT Cloud Forwarder requires a dedicated S3 bucket per log type (cannot mix VPC and ELB logs in the same bucket)
- **Same region deployment**: The CloudFormation stack must be deployed in the same region as the S3 bucket
- **Lambda-based**: Each stack deploys a Lambda function triggered by S3 events

## CloudFormation Template

The tool uses Elastic's published CloudFormation template:
```
https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml
```

Also available via AWS Serverless Application Repository as `edot-cloud-forwarder-s3-logs`.

## Troubleshooting

### No sources found

- Verify you have VPC Flow Logs or ELB Access Logs configured to write to S3
- Check you're scanning the correct region
- Ensure your IAM permissions include `ec2:DescribeFlowLogs` and `elasticloadbalancing:Describe*`

### Permission denied errors

Your AWS credentials need the following permissions:
- `ec2:DescribeFlowLogs`
- `elasticloadbalancing:DescribeLoadBalancers`
- `elasticloadbalancing:DescribeLoadBalancerAttributes`
- `sts:GetCallerIdentity`

### CloudFormation deployment fails

- Verify the S3 bucket exists and is in the same region as the stack
- Check your Elastic API key is valid
- Ensure `CAPABILITY_NAMED_IAM` is accepted (the script handles this automatically)

## Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run linting
python -m py_compile discover.py
```

## License

Apache 2.0
