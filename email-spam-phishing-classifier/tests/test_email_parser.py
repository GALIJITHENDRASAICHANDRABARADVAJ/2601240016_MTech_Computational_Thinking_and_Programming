import tempfile
import unittest
from pathlib import Path

from tests.helpers import EML_DIR, build_eml
from src.email_parser import (
    EmailParseError,
    load_emails,
    normalize_label,
    parse_csv_text,
    parse_eml_bytes,
    parse_eml_file,
)


class NormalizeLabelTests(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(normalize_label("HAM"), "legitimate")
        self.assertEqual(normalize_label(" Phish "), "phishing")
        self.assertEqual(normalize_label("not_spam"), "legitimate")
        self.assertEqual(normalize_label("junk"), "spam")

    def test_empty_is_none(self):
        self.assertIsNone(normalize_label(""))
        self.assertIsNone(normalize_label(None))

    def test_unknown_raises(self):
        with self.assertRaises(EmailParseError):
            normalize_label("maybe")


class EmlParsingTests(unittest.TestCase):
    def test_basic_headers(self):
        raw = build_eml(sender='"Support Team" <Help@Example.COM>', subject="Re: your ticket", reply_to="other@elsewhere.org")
        e = parse_eml_bytes(raw, source="x.eml", email_id="x")
        self.assertEqual(e.from_name, "Support Team")
        self.assertEqual(e.from_addr, "help@example.com")
        self.assertEqual(e.reply_to_addr, "other@elsewhere.org")
        self.assertEqual(e.subject, "Re: your ticket")
        self.assertIn("Hi there", e.body_text)

    def test_multipart_text_html_and_attachment_metadata_only(self):
        raw = build_eml(text="plain part", html="<p>html part</p>", attachment=("report.pdf.exe", b"x" * 123))
        e = parse_eml_bytes(raw)
        self.assertIn("plain part", e.body_text)
        self.assertIn("html part", e.body_html)
        self.assertEqual([a.filename for a in e.attachments], ["report.pdf.exe"])
        self.assertEqual(e.attachments[0].size, 123)

    def test_authentication_results_parsed(self):
        raw = build_eml(extra_headers={"Authentication-Results": "mx.test; spf=pass smtp.mailfrom=a.b; dkim=fail; dmarc=none"})
        e = parse_eml_bytes(raw)
        self.assertEqual(e.auth, {"spf": "pass", "dkim": "fail", "dmarc": "none"})

    def test_received_spf_fallback_and_missing(self):
        e = parse_eml_bytes(build_eml(extra_headers={"Received-SPF": "softfail (domain does not designate)"}))
        self.assertEqual(e.auth["spf"], "softfail")
        self.assertEqual(e.auth["dkim"], "missing")
        self.assertEqual(e.auth["dmarc"], "missing")

    def test_empty_input_raises(self):
        with self.assertRaises(EmailParseError):
            parse_eml_bytes(b"   \n")

    def test_no_headers_raises(self):
        with self.assertRaises(EmailParseError):
            parse_eml_bytes(b"this is just a sentence without any header")

    def test_unknown_charset_does_not_crash(self):
        raw = (b"From: a@b.example\nSubject: x\nContent-Type: text/plain; charset=made-up-charset\n"
               b"Content-Transfer-Encoding: 8bit\n\ncaf\xe9 body\n")
        e = parse_eml_bytes(raw)
        self.assertIn("body", e.body_text)

    def test_label_inferred_from_filename(self):
        e = parse_eml_file(EML_DIR / "phishing_paypal_lookalike.eml")
        self.assertEqual(e.true_label, "phishing")
        self.assertEqual(e.email_id, "phishing_paypal_lookalike")

    def test_body_truncated(self):
        e = parse_eml_bytes(build_eml(text="a" * 5000), max_body_chars=100)
        self.assertLessEqual(len(e.body_text), 100)


class CsvParsingTests(unittest.TestCase):
    CSV = (
        'id,label,from,reply-to,subject,body,SPF,dkim,dmarc,attachments\n'
        'a1,spam,"Shop <s@shop.example>",,Big sale,"line one\nline two",pass,pass,none,"a.pdf;b.exe"\n'
        'a2,ham,x@y.example,,Hi,"<html><body><a href=""http://q.example"">q</a></body></html>",,,,\n'
    )

    def test_columns_aliases_multiline_and_attachments(self):
        emails, errors = parse_csv_text(self.CSV, source="t.csv")
        self.assertEqual(errors, [])
        self.assertEqual(len(emails), 2)
        first = emails[0]
        self.assertEqual(first.email_id, "a1")
        self.assertEqual(first.true_label, "spam")
        self.assertIn("line two", first.body_text)
        self.assertEqual(first.auth, {"spf": "pass", "dkim": "pass", "dmarc": "none"})
        self.assertEqual([a.filename for a in first.attachments], ["a.pdf", "b.exe"])

    def test_html_detected(self):
        emails, _ = parse_csv_text(self.CSV, source="t.csv")
        self.assertTrue(emails[1].body_html)
        self.assertEqual(emails[1].body_text, "")
        self.assertEqual(emails[1].true_label, "legitimate")

    def test_bad_rows_are_collected_not_fatal(self):
        text = "subject,body,label\nok,fine,spam\nbad,row,maybe\n,,\n"
        emails, errors = parse_csv_text(text, source="t.csv")
        self.assertEqual(len(emails), 1)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("Unknown label" in e for e in errors))
        self.assertTrue(any("empty" in e for e in errors))

    def test_missing_required_columns_raises(self):
        with self.assertRaises(EmailParseError):
            parse_csv_text("foo,bar\n1,2\n", source="t.csv")

    def test_generated_ids_when_missing(self):
        emails, _ = parse_csv_text("subject,body\nA,b\nC,d\n", source="data.csv")
        self.assertEqual([e.email_id for e in emails], ["data-row2", "data-row3"])

    def test_short_rows_do_not_crash(self):
        emails, errors = parse_csv_text("subject,body,sender\nonly subject\n", source="t.csv")
        self.assertEqual(len(emails), 1)
        self.assertEqual(errors, [])


class LoadEmailsTests(unittest.TestCase):
    def test_directory_of_eml(self):
        emails, errors = load_emails(EML_DIR)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(emails), 6)

    def test_missing_path(self):
        with self.assertRaises(EmailParseError):
            load_emails("/definitely/not/here.csv")

    def test_unsupported_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "mail.txt"
            p.write_text("hello")
            with self.assertRaises(EmailParseError):
                load_emails(p)

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(EmailParseError):
                load_emails(tmp)

    def test_bad_eml_in_directory_is_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "good.eml").write_bytes(build_eml())
            (Path(tmp) / "bad.eml").write_bytes(b"")
            emails, errors = load_emails(tmp)
            self.assertEqual(len(emails), 1)
            self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
