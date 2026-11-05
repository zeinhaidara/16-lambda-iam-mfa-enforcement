"""Lambda handler: enforce MFA on newly created IAM users.

Triggered by an EventBridge rule matching the CloudTrail `CreateUser` event.
On each invocation it attaches a deny-without-MFA policy to the new user and
publishes a notification. Both steps are idempotent, so redelivery of the
same event is safe.
"""

import json
import os

import boto3

MFA_POLICY_NAME = "EnforceMFAForNewUsers"

MFA_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowViewAccountInfo",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:ListVirtualMFADevices",
            ],
            "Resource": "*",
        },
        {
            "Sid": "AllowManageOwnMFA",
            "Effect": "Allow",
            "Action": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:ListMFADevices",
                "iam:ResyncMFADevice",
            ],
            "Resource": [
                "arn:aws:iam::*:mfa/${aws:username}",
                "arn:aws:iam::*:user/${aws:username}",
            ],
        },
        {
            "Sid": "AllowManageOwnCredentials",
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:GetUser",
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}",
        },
        {
            "Sid": "DenyAllExceptListedUnlessMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:ListMFADevices",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "iam:GetUser",
                "iam:ChangePassword",
                "iam:GetAccountPasswordPolicy",
                "sts:GetSessionToken",
            ],
            "Resource": "*",
            "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
        },
    ],
}


def _extract_username(event):
    """Pull the new IAM user name out of a CloudTrail CreateUser event."""
    detail = event.get("detail", event)
    request_params = detail.get("requestParameters") or {}
    username = request_params.get("userName")
    if not username:
        raise ValueError("event does not contain an IAM userName")
    return username


def _policy_arn(account_id, policy_name):
    return f"arn:aws:iam::{account_id}:policy/{policy_name}"


def ensure_mfa_policy_exists(iam_client, account_id, policy_name=MFA_POLICY_NAME):
    """Create the managed policy if it doesn't exist yet. Returns its ARN."""
    arn = _policy_arn(account_id, policy_name)
    try:
        iam_client.get_policy(PolicyArn=arn)
        return arn
    except iam_client.exceptions.NoSuchEntityException:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MFA_POLICY_DOCUMENT),
            Description="Denies actions for IAM users that have not enabled MFA",
        )
        return response["Policy"]["Arn"]


def attach_mfa_policy(iam_client, username, policy_arn):
    """Attach the policy to the user. A no-op if already attached."""
    iam_client.attach_user_policy(UserName=username, PolicyArn=policy_arn)


def notify(sns_client, topic_arn, username, policy_arn):
    if not topic_arn:
        return
    message = (
        f"IAM user '{username}' was created and the MFA-enforcement policy "
        f"({policy_arn}) has been attached. The user must enable MFA to "
        "perform most actions."
    )
    sns_client.publish(
        TopicArn=topic_arn,
        Subject="New IAM user enrolled in MFA enforcement",
        Message=message,
    )


def handler(event, context):
    sts_client = boto3.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]

    iam_client = boto3.client("iam")
    sns_client = boto3.client("sns")
    topic_arn = os.environ.get("NOTIFICATION_TOPIC_ARN")

    username = _extract_username(event)
    policy_arn = ensure_mfa_policy_exists(iam_client, account_id)
    attach_mfa_policy(iam_client, username, policy_arn)
    notify(sns_client, topic_arn, username, policy_arn)

    return {
        "username": username,
        "policyArn": policy_arn,
        "notified": bool(topic_arn),
    }
