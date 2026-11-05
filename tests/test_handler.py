import json
import os
import unittest
from unittest.mock import MagicMock

import handler


class ExtractUsernameTests(unittest.TestCase):
    def test_extracts_username_from_cloudtrail_event(self):
        with open("examples/sample-event.json") as f:
            event = json.load(f)
        self.assertEqual(handler._extract_username(event), "jsmith")

    def test_missing_username_raises(self):
        with self.assertRaises(ValueError):
            handler._extract_username({"detail": {"requestParameters": {}}})


class EnsureMfaPolicyTests(unittest.TestCase):
    def test_creates_policy_when_missing(self):
        iam = MagicMock()
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_policy.side_effect = iam.exceptions.NoSuchEntityException()
        iam.create_policy.return_value = {
            "Policy": {"Arn": "arn:aws:iam::123456789012:policy/EnforceMFAForNewUsers"}
        }

        arn = handler.ensure_mfa_policy_exists(iam, "123456789012")

        self.assertEqual(arn, "arn:aws:iam::123456789012:policy/EnforceMFAForNewUsers")
        iam.create_policy.assert_called_once()

    def test_reuses_existing_policy(self):
        iam = MagicMock()
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_policy.return_value = {"Policy": {"Arn": "irrelevant"}}

        arn = handler.ensure_mfa_policy_exists(iam, "123456789012")

        self.assertEqual(arn, "arn:aws:iam::123456789012:policy/EnforceMFAForNewUsers")
        iam.create_policy.assert_not_called()


class AttachMfaPolicyTests(unittest.TestCase):
    def test_attaches_policy_to_user(self):
        iam = MagicMock()

        handler.attach_mfa_policy(iam, "jsmith", "arn:aws:iam::123456789012:policy/x")

        iam.attach_user_policy.assert_called_once_with(
            UserName="jsmith", PolicyArn="arn:aws:iam::123456789012:policy/x"
        )


class NotifyTests(unittest.TestCase):
    def test_publishes_when_topic_configured(self):
        sns = MagicMock()

        handler.notify(sns, "arn:aws:sns:us-east-1:123456789012:topic", "jsmith", "policy-arn")

        sns.publish.assert_called_once()
        kwargs = sns.publish.call_args.kwargs
        self.assertIn("jsmith", kwargs["Message"])
        self.assertEqual(kwargs["TopicArn"], "arn:aws:sns:us-east-1:123456789012:topic")

    def test_skips_publish_when_no_topic(self):
        sns = MagicMock()

        handler.notify(sns, None, "jsmith", "policy-arn")

        sns.publish.assert_not_called()


class HandlerTests(unittest.TestCase):
    def test_handler_end_to_end(self):
        with open("examples/sample-event.json") as f:
            event = json.load(f)

        iam = MagicMock()
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_policy.return_value = {"Policy": {"Arn": "irrelevant"}}
        sns = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}

        clients = {"iam": iam, "sns": sns, "sts": sts}

        import boto3

        original_client = boto3.client
        boto3.client = lambda name, *a, **kw: clients[name]
        try:
            result = handler.handler(event, None)
        finally:
            boto3.client = original_client

        self.assertEqual(result["username"], "jsmith")
        iam.attach_user_policy.assert_called_once_with(
            UserName="jsmith",
            PolicyArn="arn:aws:iam::123456789012:policy/EnforceMFAForNewUsers",
        )
        sns.publish.assert_not_called()

    def test_handler_publishes_when_topic_env_set(self):
        with open("examples/sample-event.json") as f:
            event = json.load(f)

        iam = MagicMock()
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_policy.return_value = {"Policy": {"Arn": "irrelevant"}}
        sns = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}

        clients = {"iam": iam, "sns": sns, "sts": sts}

        import boto3

        original_client = boto3.client
        boto3.client = lambda name, *a, **kw: clients[name]
        os.environ["NOTIFICATION_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:topic"
        try:
            result = handler.handler(event, None)
        finally:
            boto3.client = original_client
            del os.environ["NOTIFICATION_TOPIC_ARN"]

        self.assertTrue(result["notified"])
        sns.publish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
