import json
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
sns = boto3.client("sns")
table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
PREFIX = os.environ.get("SCOPE_PREFIX", "cs-demo-")
TOPIC_ARN = os.environ["TOPIC_ARN"]

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def fix_s3(f):
    bucket = f["resource"]
    if not bucket.startswith(PREFIX):
        return "SKIPPED", "Out of scope"
    if DRY_RUN:
        return "DRY_RUN", "Would enable Block Public Access"
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=FULL_BLOCK)
    return "FIXED", "Block Public Access enabled"


def fix_sg(f):
    group_id = f["resource"]
    try:
        groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            return "SKIPPED", "Security group no longer exists"
        raise
    if not groups[0]["GroupName"].startswith(PREFIX):
        return "SKIPPED", "Out of scope"
    rules = json.loads(f["details"])["rules"]
    if DRY_RUN:
        return "DRY_RUN", f"Would revoke {len(rules)} world-open SSH rule(s)"
    for r in rules:
        perm = {"IpProtocol": r["protocol"]}
        if r["protocol"] != "-1":
            perm["FromPort"] = r["from"]
            perm["ToPort"] = r["to"]
        if r["family"] == "ipv4":
            perm["IpRanges"] = [{"CidrIp": r["cidr"]}]
        else:
            perm["Ipv6Ranges"] = [{"CidrIpv6": r["cidr"]}]
        try:
            ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[perm])
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidPermission.NotFound":
                raise
    return "FIXED", f"Revoked {len(rules)} world-open SSH rule(s)"


FIXERS = {"S3_PUBLIC_ACCESS": fix_s3, "SG_OPEN_SSH": fix_sg}


def mark(f, status, result):
    table.update_item(
        Key={"finding_id": f["finding_id"]},
        UpdateExpression="SET #s = :s, #r = :r, updated_at = :t",
        ExpressionAttributeNames={"#s": "status", "#r": "result"},
        ExpressionAttributeValues={
            ":s": status,
            ":r": result,
            ":t": datetime.now(timezone.utc).isoformat(),
        },
    )


def lambda_handler(event, context):
    for record in event["Records"]:
        f = json.loads(record["body"])
        try:
            status, result = FIXERS[f["rule"]](f)
        except Exception as e:
            # Leave a trace in the audit table, then let SQS retry (and later use the DLQ).
            try:
                mark(f, "RETRYING", str(e)[:200])
            except Exception:
                pass
            raise
        mark(f, status, result)
        message = (
            f"Rule: {f['rule']}\n"
            f"Resource: {f['resource']}\n"
            f"Risk score: {f['risk']}\n"
            f"Risky action: {f['action']}\n"
            f"Done by: {f['actor']}\n"
            f"Status: {status}\n"
            f"Result: {result}"
        )
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"CloudSentinel: {status} {f['rule']}"[:100],
            Message=message,
        )
        print(message)
    return {"status": "ok"}

