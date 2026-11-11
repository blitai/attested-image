"""AWS credentials for a run's own processes on a worker.

The run Lambda leaves credentials limited to the run (its project's folder,
an attested run's control files, its Parameter Store entries) at
s3://<bucket>/creds/<this instance's ARN>, and renews them every 20 minutes
(lambdas run_simulation: _grant_creds). use() makes them what boto3 and the
AWS CLI use in this process and its children, through credential_process, so
a run can't reach other users' files even if something in it is subverted.
Where the Lambda left none (an older Lambda, a warm-up), the instance role's
own credentials are returned, as before.

Run as a script, it prints the credentials in credential_process's format.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.join(HERE, "run_creds.conf")
WORKER_PATHS = ("/home/ubuntu/compute/utils",   # where workers check compute out
                "/opt/blit/utils")              # the attested image's own copy
BUCKET = "blitai-dev-bucket"
IMDS = "http://169.254.169.254/latest"


def use():
    """On a worker, route this process's AWS credentials through here."""
    if HERE in WORKER_PATHS and os.path.exists(CONF):
        os.environ["AWS_CONFIG_FILE"] = CONF
        os.environ.pop("AWS_PROFILE", None)


def _imds(path, token):
    import urllib.request
    req = urllib.request.Request(f"{IMDS}/{path}", headers={"X-aws-ec2-metadata-token": token})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.read().decode()


def main():
    import urllib.request
    os.environ.pop("AWS_CONFIG_FILE", None)   # boto3 below must not call back into this script
    req = urllib.request.Request(f"{IMDS}/api/token", method="PUT",
                                 headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
    with urllib.request.urlopen(req, timeout=5) as r:
        token = r.read().decode()
    doc = json.loads(_imds("dynamic/instance-identity/document", token))
    role = _imds("meta-data/iam/security-credentials/", token).split()[0]
    inst = json.loads(_imds(f"meta-data/iam/security-credentials/{role}", token))
    out = {"Version": 1, "AccessKeyId": inst["AccessKeyId"], "SecretAccessKey": inst["SecretAccessKey"],
           "SessionToken": inst["Token"], "Expiration": inst["Expiration"]}
    import boto3
    s3 = boto3.client("s3", region_name="us-east-1", aws_access_key_id=inst["AccessKeyId"],
                      aws_secret_access_key=inst["SecretAccessKey"], aws_session_token=inst["Token"])
    arn = f"arn:aws:ec2:{doc['region']}:{doc['accountId']}:instance/{doc['instanceId']}"
    from botocore.exceptions import ClientError
    try:
        run = json.loads(s3.get_object(Bucket=BUCKET, Key=f"creds/{arn}")["Body"].read())
        out = {"Version": 1, **{k: run[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")}}
    except ClientError as e:
        # None left for this instance (without ListBucket a missing key reads as AccessDenied)
        if e.response.get("Error", {}).get("Code") not in ("NoSuchKey", "AccessDenied"):
            raise
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
