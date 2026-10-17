import unittest

from tests.helpers import default_config, email
from src.classifier import EmailClassifier, decide_label


class DecideLabelTests(unittest.TestCase):
    T = {"phishing": 50.0, "spam": 40.0}

    def test_below_thresholds_is_legitimate(self):
        self.assertEqual(decide_label(49.9, 39.9, self.T), "legitimate")

    def test_single_category(self):
        self.assertEqual(decide_label(50, 0, self.T), "phishing")
        self.assertEqual(decide_label(0, 40, self.T), "spam")

    def test_higher_score_wins_when_both_qualify(self):
        self.assertEqual(decide_label(60, 80, self.T), "spam")
        self.assertEqual(decide_label(80, 60, self.T), "phishing")

    def test_tie_goes_to_phishing(self):
        self.assertEqual(decide_label(70, 70, self.T), "phishing")


class ClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clf = EmailClassifier()

    def test_obvious_phishing(self):
        e = email(
            sender="PayPal Security <service@paypa1-secure.top>", reply_to="x@gmail.com",
            subject="Account limited",
            body="Verify your account and confirm your password within 24 hours: http://paypa1-secure.top/login",
            auth={"spf": "fail", "dkim": "none", "dmarc": "fail"},
        )
        r = self.clf.classify(e)
        self.assertEqual(r.label, "phishing")
        self.assertGreaterEqual(r.risk_score, 50)
        ids = {m.rule_id for m in r.matches}
        self.assertTrue({"PH01", "PH02", "PH06"} <= ids)

    def test_obvious_spam(self):
        e = email(
            sender="Deals <deals@megadeals.example>", subject="AMAZING OFFER!!! ORDER NOW!!!",
            body="You have won a free gift! Click here, limited time, act now! Cheap discount, best price.",
        )
        r = self.clf.classify(e)
        self.assertEqual(r.label, "spam")
        self.assertGreater(r.spam_score, r.phishing_score)

    def test_obvious_legitimate(self):
        e = email(
            sender="Priya <priya@acme.example>", subject="Meeting notes",
            body="Hi, attached are the notes from today's meeting. Thanks.",
            auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        )
        r = self.clf.classify(e)
        self.assertEqual(r.label, "legitimate")
        self.assertEqual(r.risk_score, 0.0)

    def test_explanation_contains_rules_scores_and_label(self):
        e = email(sender="x@gmail.com", subject="s", body="URGENT: verify your account now http://192.0.2.9/login")
        r = self.clf.classify(e)
        self.assertIn(r.label.upper(), r.explanation)
        self.assertIn(f"{r.risk_score:.1f}", r.explanation)
        for m in r.matches:
            self.assertIn(m.rule_id, r.explanation)
            self.assertIn(m.detail, r.explanation)

    def test_result_metadata(self):
        e = email(sender="a@b.example", subject="Hello", body="hi", true_label="legitimate")
        r = self.clf.classify(e)
        self.assertEqual(r.true_label, "legitimate")
        self.assertEqual(r.email_id, "t1")
        self.assertGreaterEqual(r.elapsed_ms, 0)
        self.assertGreater(r.rules_evaluated, 0)
        self.assertIsInstance(r.to_dict(), dict)

    def test_thresholds_are_configurable(self):
        e = email(sender="a@b.example", subject="s", body="Limited time! Click here for a free gift.")
        default = EmailClassifier().classify(e)
        strict_cfg = default_config()
        strict_cfg["thresholds"]["spam"] = 5
        strict = EmailClassifier(config=strict_cfg).classify(e)
        self.assertEqual(default.label, "legitimate")
        self.assertEqual(strict.label, "spam")

    def test_weights_are_configurable(self):
        e = email(sender="a@b.example", subject="s", body="limited time click here free gift act now")
        cfg = default_config()
        for rule in cfg["rules"]:
            if rule["id"] == "SP01":
                rule["per_hit"] = 1
        weaker = EmailClassifier(config=cfg).classify(e)
        self.assertLess(weaker.spam_score, EmailClassifier().classify(e).spam_score)

    def test_classify_safe_converts_errors(self):
        class Boom:
            email_id, source, from_raw, subject, true_label = "boom", "test", "", "", None

        r = self.clf.classify_safe(Boom())  # type: ignore[arg-type]
        self.assertEqual(r.label, "error")
        self.assertFalse(r.ok)
        self.assertIn("failed", r.explanation.lower())

    def test_handles_empty_email(self):
        r = self.clf.classify(email())
        self.assertIn(r.label, ("legitimate", "spam", "phishing"))

    def test_invalid_config_path(self):
        from src.config import ConfigError
        with self.assertRaises(ConfigError):
            EmailClassifier(config_path="/no/such/rules.json")


if __name__ == "__main__":
    unittest.main()
