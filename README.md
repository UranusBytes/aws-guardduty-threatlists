# update_guardduty_threat-list.py

## Table of Contents
* [Description](#description)
* [Configuration](#Configuration)
* [Troubleshooting](#troubleshooting)
* [License](#license)

## Description
This script will download a copy of a threatlist (or multiple), reformat it, upload to an S3 bucket, and then configure/refresh AWS GuardDuty to use the threatlist.  

This script has gone thru basic testing sufficient for my environment (CentOS 7 w/ Python 3.6 and OTX threatlist) and usage.  

This script assumes that GuardDuty has been enabled and has detectors configured in all regions that threatlists will be uploaded to, as well as assumes there are other means for collection/alerting of findings.

## Execution
Normally you would have this script as a cron/scheduled job to execute on some frequency to update the guardduty threatlists.  FWIW, the open OTX is updated every 6hrs.  More frequent updates could have unknown implications to GuardDuty

## Configuration
All configuration for the script is done thru the Constants defined at the top of the file, starting around line 35, under the section named `Constants`
### _THREAT_LISTS
This is where threat lists are defined.  The default config is to use AlienVault's OTX.
```
_THREATLISTS = [
  {
    'list_name': 'OTX_Reputation',
    'list_url': 'https://reputation.alienvault.com/reputation.generic.gz',
    'list_format': 'TXT'
  }
]
```
### THREATLIST_S3_BUCKET
This is the S3 bucket name that the threatlist will be uploaded to.

`_THREATLIST_S3_BUCKET = 'myBucket'`
This would upload the file to `https://s3.amazonaws.com/myBucket/myKeyPath/OTX_Reputation.txt`

### _THREATLIST_S3_KEY_PATH
This is the key path (without a pre or post slash) that will be used in the S3 bucket to store the threatlist.

`_THREATLIST_S3_KEY_PATH = 'myKeyPath'`
This would upload the file to `https://s3.amazonaws.com/myBucket/myKeyPath/OTX_Reputation.txt`

### AWS_REGIONS
This is a list that defines the regions that the threatlist will be configured for.  To define specific regions, the format would be:
`_AWS_REGIONS = ['us-east-1', 'us-east-2']`

To configure for all regions supported by guardduty, the format would be:
`_AWS_REGIONS = boto3.Session().get_available_regions(service_name='guardduty', partition_name='aws')`

## Required IAM Permissions
The following IAM permissions are required by the IAM user/role used to execute the script.  If the S3 bucket is cross account, if the S3 bucket is using KMS, or different configurations may require different permissions. 

**Note**: Change the ServiceRole ARN to the appropriate service role being used for GuardDuty

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::myBucketName/myKeyPath/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "guardduty:ListDetectors",
                "guardduty:ListThreatIntelSets",
                "guardduty:UpdateThreatIntelSet"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:PutRolePolicy",
                "iam:DeleteRolePolicy"
            ],
            "Resource": "arn:aws:iam::123412341234:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"
        }
    ]
}
```

## Troubleshooting
There are two constants defined at the top of the plugin that can be used to facilitate debugging

`_STDERR_OUTPUT_LEVEL` Change to `logging.INFO` for verbose output to stderr (same as `-v/-verbose`) or to `logging.DEBUG` for debug output to stderr (same as `-vv/--debug`)

`_PRINT_STACKTRACE_ON_ERROR` Change to `True` to have the python stacktrace output to stderr when an error occurs

## ToDo
* Consider other threatlists

## License
All content is GPLv2

