import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
sqs = boto3.client("sqs")
table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])

PREFIX = os.environ.get("SCOPE_PREFIX", "cs-demo-")
QUEUE_URL = os.environ["QUEUE_URL"]

BLOCK_KEYS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


def bucket_is_protected(bucket):
    """True if all four Block Public Access settings are on (or bucket is gone)."""
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        return all(cfg.get(k) for k in BLOCK_KEYS)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            return False
        if code == "NoSuchBucket":
            return True
        raise


def open_ssh_rules(params):
    """Return the rules that open SSH (port 22) to the whole internet."""
    rules = []
    for p in (params.get("ipPermissions") or {}).get("items", []):
        proto = str(p.get("ipProtocol"))
        if proto == "-1":
            lo, hi = 0, 65535
        elif proto in ("tcp", "6"):
            lo, hi = p.get("fromPort"), p.get("toPort")
            if lo is None or hi is None:
                continue
        else:
            continue
        if not (lo <= 22 <= hi):
            continue
        for r in (p.get("ipRanges") or {}).get("items", []):
            if r.get("cidrIp") == "0.0.0.0/0":
                rules.append({"protocol": proto, "from": p.get("fromPort"),
                              "to": p.get("toPort"), "cidr": "0.0.0.0/0",
                              "family": "ipv4"})
        for r in (p.get("ipv6Ranges") or {}).get("items", []):
            if r.get("cidrIpv6") == "::/0":
                rules.append({"protocol": proto, "from": p.get("fromPort"),
                              "to": p.get("toPort"), "cidr": "::/0",
                              "family": "ipv6"})
    return rules


def new_finding(rule, resource, action, actor, risk, details):
    return {
        "finding_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule": rule,
        "resource": resource,
        "action": action,
        "actor": actor,
        "risk": risk,
        "details": json.dumps(details),
        "status": "DETECTED",
    }


def check_s3(params, action, actor):
    bucket = params.get("bucketName")
    if not bucket or not bucket.startswith(PREFIX):
        print(f"Skipped (out of scope): {bucket}")
        return None
    if bucket_is_protected(bucket):
        print(f"Already protected: {bucket}")
        return None
    # Risk: a new ACL or policy may grant public access; removing the block is lower.
    risk = 90 if action in ("PutBucketAcl", "PutBucketPolicy") else 75
    return new_finding("S3_PUBLIC_ACCESS", bucket, action, actor, risk, {})


def check_sg(params, action, actor):
    group_id = params.get("groupId")
    rules = open_ssh_rules(params)
    if not group_id or not rules:
        print(f"No world-open SSH rule in this change: {group_id}")
        return None
    try:
        groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    except ClientError as e:
        print(f"Cannot describe {group_id}: {e.response['Error']['Code']}")
        return None
    name = groups[0]["GroupName"] if groups else ""
    if not name.startswith(PREFIX):
        print(f"Skipped (out of scope): {name}")
        return None
    # Risk: all ports open is worse than SSH only.
    risk = 95 if any(r["protocol"] == "-1" for r in rules) else 80
    return new_finding("SG_OPEN_SSH", group_id, action, actor, risk, {"rules": rules})


def lambda_handler(event, context):
    detail = event.get("detail", {})
    source = detail.get("eventSource")
    action = detail.get("eventName")
    actor = (detail.get("userIdentity") or {}).get("arn", "unknown")
    params = detail.get("requestParameters") or {}

    if source == "s3.amazonaws.com":
        finding = check_s3(params, action, actor)
    elif source == "ec2.amazonaws.com":
        finding = check_sg(params, action, actor)
    else:
        finding = None

    if finding is None:
        return {"status": "skipped"}

    table.put_item(Item=finding)
    sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(finding))
    print(f"Queued finding {finding['finding_id']} rule={finding['rule']} "
          f"resource={finding['resource']} risk={finding['risk']} actor={actor}")
    return {"status": "queued", "finding_id": finding["finding_id"]}
