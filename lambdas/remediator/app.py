import os
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
PREFIX = os.environ.get("SCOPE_PREFIX", "cs-demo-")
TOPIC_ARN = os.environ["TOPIC_ARN"]

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def is_protected(bucket):
    """True if all four Block Public Access settings are on (or bucket is gone)."""
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        return all(cfg.get(k) for k in FULL_BLOCK)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            return False
        if code == "NoSuchBucket":
            return True
        raise


def lambda_handler(event, context):
    detail = event.get("detail", {})
    bucket = (detail.get("requestParameters") or {}).get("bucketName")
    action = detail.get("eventName")
    who = detail.get("userIdentity", {}).get("arn", "unknown")

    if not bucket or not bucket.startswith(PREFIX):
        print(f"Skipped (out of scope): {bucket}")
        return {"status": "skipped"}

    if is_protected(bucket):
        print(f"Already protected: {bucket}")
        return {"status": "already_protected"}

    if DRY_RUN:
        result = "DRY RUN: would enable Block Public Access"
    else:
        s3.put_public_access_block(
            Bucket=bucket, PublicAccessBlockConfiguration=FULL_BLOCK
        )
        result = "FIXED: Block Public Access enabled"

    message = (
        f"Bucket: {bucket}\n"
        f"Risky action: {action}\n"
        f"Done by: {who}\n"
        f"Result: {result}"
    )
    sns.publish(TopicArn=TOPIC_ARN, Subject=f"CloudSentinel: {bucket}", Message=message)
    print(message)
    return {"status": "alerted", "dry_run": DRY_RUN}