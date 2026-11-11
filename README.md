# IAM MFA enforcement Lambda

A Python Lambda handler that reacts to IAM `CreateUser` events and attaches a
deny-without-MFA policy to the new user, then publishes a notification.

**Scope.** This is the handler logic plus tests, not a deployable stack: no
Terraform/CDK/SAM template is included, the Lambda is never packaged or
uploaded, and no test makes a real AWS API call. All IAM/STS/SNS calls are
exercised in tests against mocked boto3 clients. `examples/eventbridge-rule.json`
and `examples/sample-event.json` show the event shape this handler expects;
wiring an actual EventBridge rule + Lambda + IAM execution role is left to the
consumer.

## Problem statement

Implement a Python Lambda that is triggered on new IAM user creation and
automatically attaches an MFA-enforcement policy and sends a notification.

## Architecture

```
IAM CreateUser  -->  CloudTrail  -->  EventBridge rule  -->  Lambda (handler.py)
                                                                 |
                                                   +-------------+-------------+
                                                   |                           |
                                      iam:AttachUserPolicy            sns:Publish
                                      (EnforceMFAForNewUsers)       (notification)
```

- `handler.py` — the whole Lambda. `handler()` is the entry point: it pulls the
  account ID via STS, extracts the new user's name from the event, makes sure
  the `EnforceMFAForNewUsers` managed policy exists (creating it on first run),
  attaches it to the user, and publishes an SNS notification if
  `NOTIFICATION_TOPIC_ARN` is set.
- The policy allows a user to manage their own MFA device and credentials, and
  denies everything else unless `aws:MultiFactorAuthPresent` is `true`.
- `examples/eventbridge-rule.json` is the EventBridge event pattern that
  selects `CreateUser` calls from the CloudTrail management-events stream.
- `examples/sample-event.json` is a sample event in the shape EventBridge
  delivers to the Lambda for that rule.

## Prerequisites

- Python 3.12+
- `pip install -r requirements.txt` (`boto3` only)
- To actually deploy: an EventBridge rule using the pattern in
  `examples/eventbridge-rule.json`, a Lambda running `handler.handler` with an
  execution role granted `iam:GetPolicy`, `iam:CreatePolicy`,
  `iam:AttachUserPolicy`, and `sns:Publish` on the notification topic, and
  (optionally) the `NOTIFICATION_TOPIC_ARN` environment variable set to an SNS
  topic ARN.

## Usage

```python
from handler import handler

event = {
    "detail": {
        "eventName": "CreateUser",
        "requestParameters": {"userName": "jsmith"},
    }
}
handler(event, None)
```

Run it against the bundled sample event:

```bash
python -c "import json, handler; handler.handler(json.load(open('examples/sample-event.json')), None)"
```

(that call will fail without real AWS credentials and an IAM user named
`jsmith` — it's meant to be run against a mocked client, as the tests do, or
deployed as the actual Lambda.)

## Security considerations

- The attached policy is additive and narrow: it only denies actions when MFA
  is absent, and only allows the minimum actions needed to self-enroll in MFA
  (`iam:CreateVirtualMFADevice`, `iam:EnableMFADevice`, etc.) plus
  `sts:GetSessionToken` so a user without MFA can still obtain temporary
  credentials to complete enrollment.
- The Lambda's own execution role should be scoped to exactly the four
  actions above — nothing broader.
- No secrets are read, logged, or required by the handler.
- The notification message includes the username and policy ARN only; no
  credentials or secrets are ever included in the SNS payload.

## Idempotency

- `ensure_mfa_policy_exists` checks for the policy before creating it, so
  redelivery of the same (or a different) `CreateUser` event never creates
  duplicate policies.
- `iam:AttachUserPolicy` is itself idempotent in AWS — attaching an
  already-attached policy to a user is a no-op, not an error.
- Re-running the handler for the same user multiple times results in the same
  end state: one policy attached, one notification sent per invocation.

## Validation

```bash
pip install -r requirements-test.txt
python -m unittest discover -s tests
```

Tests mock all boto3 clients (IAM, SNS, STS) — no AWS credentials or network
access required. Coverage includes: extracting the username from a CloudTrail
event, a missing-username error path, creating the policy when absent,
reusing it when it already exists, attaching the policy, publishing (and
skipping) the notification depending on whether a topic ARN is configured,
and two full end-to-end handler runs (with and without notification enabled).

## Status

Implemented and unit-tested against mocked AWS clients. Not deployed; no
live AWS calls have been exercised. Deploying requires wiring the Lambda,
EventBridge rule, SNS topic, and IAM execution role yourself using the
samples in `examples/` as a starting point.
