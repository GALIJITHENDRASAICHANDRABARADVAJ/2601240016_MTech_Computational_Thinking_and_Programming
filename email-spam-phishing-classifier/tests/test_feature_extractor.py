import unittest

from tests.helpers import default_config, email
from src.feature_extractor import FeatureExtractor, is_ip_host, registered_domain


class DomainHelperTests(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(registered_domain("mail.example.co.uk"), "example.co.uk")
        self.assertEqual(registered_domain("example.com"), "example.com")
        self.assertEqual(registered_domain("192.0.2.1"), "192.0.2.1")
        self.assertEqual(registered_domain(""), "")

    def test_is_ip_host(self):
        self.assertTrue(is_ip_host("192.0.2.45"))
        self.assertTrue(is_ip_host("3232235777"))
        self.assertTrue(is_ip_host("0xc0a80001"))
        self.assertFalse(is_ip_host("example.com"))
        self.assertFalse(is_ip_host(""))


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.fx = FeatureExtractor(default_config())

    def f(self, **kw):
        return self.fx.extract(email(**kw))

    # ---- header features
    def test_reply_to_mismatch(self):
        f = self.f(sender="A <a@bank.example>", reply_to="x@gmail.com", subject="s", body="b")
        self.assertTrue(f["reply_to_mismatch"])
        self.assertFalse(self.f(sender="A <a@bank.example>", reply_to="b@mail.bank.example", subject="s", body="b")["reply_to_mismatch"])

    def test_lookalike_domain_leetspeak(self):
        self.assertEqual(self.f(sender="x@paypa1-secure.top", subject="s", body="b")["lookalike_brand_domain"], "PayPal")
        self.assertEqual(self.f(sender="x@micr0soft-support.com", subject="s", body="b")["lookalike_brand_domain"], "Microsoft")

    def test_real_brand_domain_not_flagged(self):
        f = self.f(sender="PayPal <service@paypal.com>", subject="s", body="b")
        self.assertEqual(f["lookalike_brand_domain"], "")
        self.assertEqual(f["display_name_brand_mismatch"], "")
        f = self.f(sender="Amazon <x@mail.amazon.com>", subject="s", body="b")
        self.assertEqual(f["display_name_brand_mismatch"], "")

    def test_display_name_brand_mismatch(self):
        f = self.f(sender="Microsoft Account Team <helpdesk@gmail.com>", subject="s", body="b")
        self.assertEqual(f["display_name_brand_mismatch"], "Microsoft")

    def test_short_brand_keywords_need_whole_token(self):
        # 'purchase' contains 'chase' but must not be flagged
        self.assertEqual(self.f(sender="x@purchase-orders.example", subject="s", body="b")["lookalike_brand_domain"], "")
        self.assertEqual(self.f(sender="x@chase-alerts.com", subject="s", body="b")["lookalike_brand_domain"], "Chase")

    def test_executive_free_mail(self):
        self.assertTrue(self.f(sender="Jane Roe (CEO) <jane@gmail.com>", subject="s", body="b")["executive_free_mail"])
        self.assertFalse(self.f(sender="Jane Roe (CEO) <jane@corp.example>", subject="s", body="b")["executive_free_mail"])

    def test_auth_counts(self):
        f = self.f(sender="a@b.example", subject="s", body="b", auth={"spf": "fail", "dkim": "pass", "dmarc": "pass"})
        self.assertEqual(f["auth_fail_count"], 1)
        self.assertEqual(f["auth_pass_count"], 2)
        self.assertTrue(f["auth_present"])
        self.assertFalse(self.f(sender="a@b.example", subject="s", body="b")["auth_present"])

    # ---- content features
    def test_keyword_families(self):
        body = ("URGENT: verify your account immediately. Your account has been suspended? No - unauthorized access. "
                "You have won the lottery, claim your prize! Click here for a free gift.")
        f = self.f(sender="a@b.example", subject="Winner", body=body)
        self.assertIn("urgent", f["urgency_phrases"])
        self.assertIn("verify your account", f["credential_phrases"])
        self.assertIn("unauthorized access", f["threat_phrases"])
        self.assertIn("lottery", f["financial_lure_phrases"])
        self.assertIn("click here", f["spam_keywords"])
        self.assertGreaterEqual(f["exclamation_count"], 1)

    def test_keywords_counted_once_per_distinct_phrase(self):
        f = self.f(sender="a@b.example", subject="s", body="urgent urgent urgent urgent")
        self.assertEqual(f["urgency_count"], 1)

    def test_word_boundaries(self):
        f = self.f(sender="a@b.example", subject="s", body="The sunburst otpimal presenting")  # 'otp' inside words
        self.assertEqual(f["credential_count"], 0)

    def test_caps_ratio_needs_enough_letters(self):
        self.assertEqual(self.f(sender="a@b.example", subject="OK", body="YES")["caps_ratio"], 0.0)
        f = self.f(sender="a@b.example", subject="s", body="THIS IS ALL CAPITAL LETTERS TEXT HERE")
        self.assertGreater(f["caps_ratio"], 0.9)

    def test_unsubscribe_detection(self):
        self.assertTrue(self.f(sender="a@b.example", subject="s", body="Click to Unsubscribe")["has_unsubscribe"])
        self.assertTrue(self.f(sender="a@b.example", subject="s", body="x", headers={"list-unsubscribe": "<mailto:u@x>"})["has_unsubscribe"])

    # ---- URLs
    def test_url_flags(self):
        body = ("http://192.0.2.45/login http://user@evil.example/x http://xn--pple-43d.com/v "
                "http://bit.ly/abc http://login.example.top/a http://a.b.c.d.example.com/ "
                "http://very-long-secure-login.example.net/")
        f = self.f(sender="a@b.example", subject="s", body=body)
        for flag in ("ip_host", "at_symbol", "punycode", "shortener", "suspicious_tld", "many_subdomains", "excess_hyphens"):
            self.assertIn(flag, f["url_flags"], flag)
        self.assertEqual(f["url_count"], 7)

    def test_url_brand_mismatch_and_legit_brand_url(self):
        f = self.f(sender="a@b.example", subject="s", body="http://amazon.com.evil-site.example/login")
        self.assertEqual(f["url_brand_mismatch"], "Amazon")
        f = self.f(sender="a@b.example", subject="s", body="https://www.amazon.com/gp/css/order-history")
        self.assertEqual(f["url_brand_mismatch"], "")

    def test_malformed_url_does_not_crash(self):
        f = self.f(sender="a@b.example", subject="s", body="see http://[invalid-url/ now")
        self.assertIn("malformed", f["url_flags"])

    def test_trailing_punctuation_stripped(self):
        f = self.f(sender="a@b.example", subject="s", body="Visit https://example.org/page.")
        self.assertEqual(f["urls"], ["https://example.org/page"])

    def test_anchor_mismatch_from_html(self):
        html = '<a href="http://evil.example/x">https://www.paypal.com/security</a>'
        f = self.f(sender="a@b.example", subject="s", body=html)
        self.assertEqual(f["anchor_mismatch_count"], 1)
        self.assertIn("paypal.com", f["anchor_mismatches"][0])

    def test_anchor_without_mismatch(self):
        html = '<a href="https://www.paypal.com/security">https://www.paypal.com/security</a>'
        self.assertEqual(self.f(sender="a@b.example", subject="s", body=html)["anchor_mismatch_count"], 0)

    def test_password_form_and_script_text_ignored(self):
        html = '<script>var x="verify your account";</script><form><input type="password"></form><p>hello</p>'
        f = self.f(sender="a@b.example", subject="s", body=html)
        self.assertTrue(f["has_password_form"])
        self.assertEqual(f["credential_count"], 0)  # text inside <script> is not visible content

    # ---- attachments
    def test_attachment_features(self):
        from src.models import Attachment
        atts = [Attachment("invoice.pdf.exe"), Attachment("a.docm"), Attachment("login.html"),
                Attachment("bundle.zip"), Attachment("notes.pdf")]
        f = self.f(sender="a@b.example", subject="s", body="b", attachments=atts)
        self.assertTrue(f["has_dangerous_attachment"])
        self.assertTrue(f["has_double_extension"])
        self.assertTrue(f["has_macro_attachment"])
        self.assertTrue(f["has_html_attachment"])
        self.assertTrue(f["has_archive_attachment"])
        self.assertEqual(f["attachment_count"], 5)

    def test_plain_pdf_is_clean(self):
        from src.models import Attachment
        f = self.f(sender="a@b.example", subject="s", body="b", attachments=[Attachment("notes.pdf")])
        self.assertFalse(f["has_dangerous_attachment"] or f["has_double_extension"] or f["has_macro_attachment"])

    # ---- robustness
    def test_empty_email(self):
        f = self.f()
        self.assertTrue(f["subject_empty"])
        self.assertEqual(f["url_count"], 0)
        self.assertEqual(f["from_domain"], "")

    def test_unicode_and_long_input(self):
        f = self.f(sender="José <jose@exämple.example>", subject="Réunión ✓", body="ñandú " * 50000)
        self.assertIn("body_length", f)


if __name__ == "__main__":
    unittest.main()
