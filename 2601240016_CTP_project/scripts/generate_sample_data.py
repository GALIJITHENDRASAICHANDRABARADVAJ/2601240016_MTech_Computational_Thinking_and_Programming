#!/usr/bin/env python3
"""Regenerate the synthetic sample data in ``data/``.

Usage (from the project root):  python scripts/generate_sample_data.py

Everything here is SYNTHETIC. Company, brand-look-alike and URL domains are invented; the IP
addresses are from the reserved documentation range 192.0.2.0/24. Nothing is ever fetched.
The dataset was written by the same author as the rules, so metrics on it are optimistic --
see docs/evaluation_and_limitations.md.
"""

from __future__ import annotations

import csv
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
EML_DIR = DATA / "eml_samples"
PASS = ("pass", "pass", "pass")
NONE = ("none", "none", "none")

# (id, label, sender, reply_to, subject, body, (spf, dkim, dmarc), attachments)
ROWS: list[tuple] = []


def add(id_, label, sender, subject, body, auth=NONE, reply_to="", attachments=""):
    ROWS.append((id_, label, sender, reply_to, subject, body, auth, attachments))


# ------------------------------------------------------------------ legitimate
add("legit-01", "legitimate", "Priya Sharma <priya.sharma@acme-corp.example>", "Team sync moved to Thursday 3 PM",
    "Hi all,\n\nThe weekly team sync has moved to Thursday at 3 PM in Conference Room B. Please add your updates "
    "to the shared agenda before the meeting.\n\nThanks,\nPriya", PASS)
add("legit-02", "legitimate", "Rahul Verma <rahul.verma@acme-corp.example>", "Sprint 14 review notes",
    "Hello team,\n\nNotes from the sprint review are on the wiki: https://wiki.acme-corp.example/sprint-14\n"
    "Please add comments by Friday.\n\nRahul", PASS)
add("legit-03", "legitimate", "Billing <billing@globex-supplies.example>", "Invoice 2026-0457 for September",
    "Please find attached invoice 2026-0457 for $1,250.00, due on October 30. Payment details are printed on "
    "the invoice. Let us know if you have any questions.", ("pass", "pass", "none"), attachments="invoice_2026-0457.pdf")
add("legit-04", "legitimate", "Cloud Weekly <news@cloudweekly.example>", "This week in cloud: 5 articles worth reading",
    "Hello,\n\nHere are this week's top stories. Read more at https://cloudweekly.example/issue/212\n\n"
    "You are receiving this because you subscribed. Unsubscribe: https://cloudweekly.example/unsubscribe", PASS)
add("legit-05", "legitimate", "GitHub <noreply@github.com>", "[GitHub] Password reset requested",
    "We received a request to reset your password. Use the link below within 3 hours: "
    "https://github.com/password_reset/abc123 . If you did not request this, you can ignore this email.", PASS)
add("legit-06", "legitimate", "Amazon.com <shipment-tracking@amazon.com>", "Your order has shipped",
    "Hello, your package will arrive on Friday. Track your package: "
    "https://www.amazon.com/progress-tracker/package/123456", PASS)
add("legit-07", "legitimate", "Contoso Bank <alerts@contosobank.example>", "Your monthly statement is ready",
    "Your September statement is now available. Sign in to your online banking through the official app or "
    "website to view it. We will never ask for your password by email.", PASS)
add("legit-08", "legitimate", "HR Team <hr@acme-corp.example>", "Updated holiday calendar 2027",
    "Hi everyone,\n\nThe holiday calendar for 2027 is attached. Please plan your leave accordingly.\n\nHR Team",
    PASS, attachments="holiday_calendar_2027.pdf")
add("legit-09", "legitimate", "Anita <anita.k1975@gmail.com>", "Photos from the weekend",
    "Hi! Sharing the photos from Sunday's picnic. Let me know which ones you like. Love, Anita", PASS)
add("legit-10", "legitimate", "IT Ops <it-ops@acme-corp.example>", "URGENT: Planned server maintenance tonight 10 PM",
    "Please save your work before 10 PM. The file server will go offline immediately after for about two hours. "
    "No action is needed from you otherwise.", PASS)
add("legit-11", "legitimate", "LinkedIn <notifications@linkedin.com>", "You have 3 new connection requests",
    '<html><body><p>Hi Sam,</p><p>You have 3 new connection requests.</p>'
    '<p><a href="https://www.linkedin.com/comm/mynetwork">View requests</a></p>'
    '<p><small><a href="https://www.linkedin.com/psettings/email">Unsubscribe</a></small></p></body></html>', PASS)
add("legit-12", "legitimate", "Bookish <hello@bookish-store.example>", "Autumn reads: new arrivals this week",
    "Our autumn sale is on! Save up to 30% on bestsellers this weekend. New members get a free trial of our "
    "audiobook app. Unsubscribe any time from your account settings.", PASS)
add("legit-13", "legitimate", "Dev Patel <dev.patel@acme-corp.example>", "Conference talk recording",
    "Here's the recording of Tuesday's talk: https://bit.ly/3AbCdEf  It's about 40 minutes.", PASS)
add("legit-14", "legitimate", "Finance <finance@acme-corp.example>", "Q3 budget workbook",
    "Attached is the Q3 budget workbook. Enable macros if you want the forecast tab to refresh.",
    PASS, attachments="q3_budget.xlsm")

# ------------------------------------------------------------------ spam
add("spam-01", "spam", "International Lottery <info@lucky-winners-intl.top>", "CONGRATULATIONS!!! YOU HAVE WON $2,500,000",
    "Dear Winner,\n\nYou have won the jackpot in our international online lottery! Your email was selected from "
    "5,000,000 entries. To claim your prize of $2,500,000 USD, contact our claims officer immediately with your "
    "full name and phone number.\n\nAct now - this offer is limited time only!!!",
    ("softfail", "none", "none"), reply_to="claims.officer2026@gmail.com")
add("spam-02", "spam", "Online Pharmacy <sales@cheap-meds-24.xyz>", "Cheap Viagra and Cialis - no prescription needed",
    "Best price on Viagra, Cialis and more. Online pharmacy, no prescription, discreet shipping. Order now and get "
    "40% discount! Click here: http://cheap-meds-24.xyz/shop")
add("spam-03", "spam", "Jobs Team <offers@easy-income-hub.click>", "Work from home and earn money fast",
    "Earn extra cash working from home. Make money fast with no experience required. Guaranteed income of $5,000 "
    "per week! 100% free to join. Click here to start: http://easy-income-hub.click/join")
add("spam-04", "spam", "VIP Casino <promo@royal-spins.top>", "Free spins + $1000 casino bonus",
    "Your exclusive VIP casino bonus is waiting. Claim your free gift: 200 free spins, no obligation. "
    "Limited time - act now! http://royal-spins.top/vip")
add("spam-05", "spam", "Slim Life <deals@slimlife-offers.example>", "Lose weight fast: miracle pill",
    "Lose weight without diet or exercise! Our miracle formula is guaranteed to work. Order now - special "
    "promotion: save up to 70%. No obligation, risk-free trial.")
add("spam-06", "spam", "Crypto Gains <invest@coinboost-pro.xyz>", "Double your Bitcoin in 24 hours",
    "Bitcoin investment opportunity! Double your money in 24 hours with guaranteed returns. Limited time - act "
    "now! Join thousands of happy investors. http://coinboost-pro.xyz/start")
add("spam-07", "spam", "Barrister James Okoro <jokoro.law@yahoo.com>", "Business proposal - confidential",
    "Dear friend,\n\nI am a barrister representing the late Engineer Roland, who died leaving an inheritance of "
    "18 million USD with no next of kin. I propose that you act as beneficiary and we share the funds 50/50. "
    "Kindly reply with your full name and phone number for the transfer funds process.\n\nRegards",
    ("pass", "pass", "pass"), reply_to="jokoro.private@gmail.com")
add("spam-08", "spam", "Growth Agency <hello@rank-boost-seo.example>", "Increase your sales with SEO services",
    "We guarantee first-page rankings. Our SEO services are the best price on the market - special promotion "
    "this month only. Increase your sales today, no obligation! To stop receiving offers, unsubscribe here.")
add("spam-09", "spam", "Luxury Watches <sales@replica-rolex-outlet.example>", "Replica Rolex watches - lowest price",
    "Replica Rolex watches at the lowest price. Free shipping worldwide. Order now! Save up to 80% - special "
    "promotion ends soon. http://replica-rolex-outlet.example/buy")
add("spam-10", "spam", "Quick Loans <apply@fastcash-loans.loan>", "Get cash today - no credit check",
    "Need cash fast? No credit check, guaranteed approval. Apply now and get up to $10,000 in your account "
    "today! Click here to apply: http://fastcash-loans.loan/apply")
add("spam-11", "spam", "Deals Daily <deals@megadeals-daily.example>", "AMAZING OFFER!!! DON'T MISS OUT - ORDER NOW!!!",
    "ONCE IN A LIFETIME DEAL! BUY NOW AND SAVE BIG! LIMITED TIME ONLY!!! CLICK HERE: http://megadeals-daily.example/offer")
add("spam-12", "spam", "List Masters <ads@bulkmail-pro.example>", "Bulk email marketing - reach 1,000,000 inboxes",
    "Bulk email services at the best price. Increase your sales with our database of 1,000,000 verified "
    "addresses. Risk-free trial, no obligation. Order now! To stop receiving offers: unsubscribe.")
add("spam-13", "spam", "Survey Rewards <rewards@survey-prize-center.example>", "You've won a free gift card!",
    "Congratulations! You've won a $100 gift card for completing our survey. Claim your reward now: "
    "http://survey-prize-center.example/claim . Offer expires today!")
add("spam-14", "spam", "Hot Deals <hot@dealz-4u.example>", "",
    "Cheap deals! Discount prices, best price guaranteed. Click here: http://dealz-4u.example/hot")
add("spam-15", "spam", "Promo Hub <promo@promo-hub.example>", "Special promotion for you",
    "Buy now and save! http://bit.ly/a1b2 http://bit.ly/c3d4 http://bit.ly/e5f6 http://bit.ly/g7h8 "
    "http://bit.ly/i9j0 - exclusive deal, limited time!")

# ------------------------------------------------------------------ phishing
add("phish-01", "phishing", "PayPal Security <service@paypa1-secure.top>",
    "Action required: Your PayPal account has been limited",
    '<html><body><p>Dear customer,</p><p>We noticed unusual activity on your account and it has been limited. '
    'To restore access you must verify your account and confirm your password within 24 hours.</p>'
    '<p><a href="http://paypa1-secure.top/login">https://www.paypal.com/restore</a></p></body></html>',
    ("fail", "none", "fail"), reply_to="paypal.resolution@gmail.com")
add("phish-02", "phishing", "Microsoft Account Team <helpdesk.office365@gmail.com>", "Your password will expire today",
    "Your Microsoft 365 password expires today. To keep your mailbox active, sign in to confirm your password "
    "now: http://ms-office-login.xyz/verify", PASS)
add("phish-03", "phishing", "Chase Online <no-reply@chase-secure-alerts.com>", "Security alert: your account has been locked",
    "Your Chase account has been locked due to suspicious activity. Confirm your identity and enter your password "
    "at http://192.0.2.45/chase/login immediately to avoid suspension.", ("fail", "none", "fail"))
add("phish-04", "phishing", "Apple Support <support@apple-id-verify.com>", "Your Apple ID has been locked",
    "Your Apple ID was used to sign in from a new device and has been locked. Verify your account: "
    "http://xn--pple-43d.com/verify", ("softfail", "none", "none"))
add("phish-05", "phishing", "DHL Express <noreply@dhl-parcel-notice.top>", "Package could not be delivered - action required",
    "Your parcel could not be delivered. Print the attached shipping label and present it at the depot. "
    "Action required within 48 hours.", attachments="shipping_label.pdf.exe")
add("phish-06", "phishing", "Accounts <accounts@vendor-payments.example>", "Payment remittance advice",
    "Please open the attached remittance advice and sign in with your email password to view it. "
    "Failure to confirm will delay your payment.", ("softfail", "none", "none"), attachments="remittance_advice.html")
add("phish-07", "phishing", "Amazon <order-update@amazon-orders.example>", "Your order could not be processed",
    '<html><body><p>Your order could not be processed. Update your billing information to avoid cancellation. '
    'Action required.</p><p><a href="http://amazon-billing-update.xyz/pay">www.amazon.com/billing</a></p></body></html>',
    ("fail", "none", "none"))
add("phish-08", "phishing", "DocuSign <dse@docusign-secure-docs.com>", "Please review and sign: Employment Agreement",
    '<html><body><p>You have a new document to review.</p>'
    '<p><a href="http://docusign-secure-docs.com/review?id=77">REVIEW DOCUMENT</a></p></body></html>')
add("phish-09", "phishing", "Netflix Billing <billing@netflix-account-update.top>", "Payment failed - update your billing",
    "Your payment was declined. Update your billing information within 24 hours or your membership will be "
    "deactivated. Update your payment: http://netflix-account-update.top/billing", ("fail", "none", "none"))
add("phish-10", "phishing", "IT Helpdesk <helpdesk.admin@outlook.com>", "Mailbox is full - verify your account",
    "Your mailbox is full and you will stop receiving messages. Verify your account and enter your password "
    "here: http://mailbox-upgrade-portal.click/owa", PASS, reply_to="it.support.desk@yahoo.com")
add("phish-11", "phishing", "Wallet Support <support@wallet-recover.xyz>", "Validate your wallet immediately",
    "Unauthorized access was detected on your crypto wallet. Revalidate your wallet by entering your recovery "
    "phrase at http://wallet-recover.xyz/validate", ("fail", "none", "none"))
add("phish-12", "phishing", "HR Payroll <payroll@acme-corp-hr.example>", "Update your direct deposit details",
    "Please confirm your account details to keep receiving your salary. Sign in to confirm: "
    "http://acme-corp-payroll-update.top/login within 24 hours.", ("none", "none", "none"),
    reply_to="hr.payroll.updates@gmail.com")
add("phish-13", "phishing", "Legal Dept <legal@contract-review.example>", "Court notice - see attached",
    "You are required to respond to the attached legal notice. Failure to respond will result in legal action.",
    attachments="court_notice.docx.scr")
add("phish-14", "phishing", "Secure Bank <alerts@securebank-verify.click>", "Verify your account now",
    '<html><body><form action="http://securebank-verify.click/post"><p>Please verify your account. Enter your '
    'password below.</p><input type="password" name="pw"><input type="submit"></form></body></html>',
    ("fail", "fail", "fail"))

# ------------------------------------------------------------------ edge cases (hard / unusual inputs)
add("edge-01", "legitimate", "Meera <meera@acme-corp.example>", "", "ok, see you then")
add("edge-02", "legitimate", "ShopRite <deals@shoprite-stores.example>", "Flash sale: limited time offer!",
    "Limited time offer! Order now and save up to 50%. Best price on everything. Discount applied at checkout. "
    "Unsubscribe from marketing emails in your account settings.", PASS)  # HARD CASE: aggressive marketing; stays 'legitimate' only because SPF/DKIM/DMARC pass
add("edge-03", "phishing", "Michael Torres (CEO) <michael.torres.ceo@gmail.com>", "Quick task - confidential",
    "Are you at your desk? I need you to handle something urgent and confidential. I am in a meeting and can't "
    "talk. Purchase 5 gift cards of $200 each and send me the codes as soon as possible.", PASS)  # KNOWN HARD CASE (BEC)
add("edge-04", "legitimate", "María García <maria.garcia@acme-corp.example>", "Reunión del lunes",
    "Hola equipo, la reunión del lunes se traslada a las 10:00. Gracias, María ✓", PASS)
add("edge-05", "legitimate", "Reports <reports@acme-corp.example>", "Quarterly report (long body)",
    "The quarterly report is ready for review. " * 400, PASS)
add("edge-06", "legitimate", "noreply@acme-corp.example", "", "", PASS)
add("edge-07", "legitimate", "Support <support@acme-corp.example>", "Link formatting test",
    "See http://[invalid-url/ and also http://exa mple.com for the malformed examples.", PASS)
add("edge-08", "phishing", "Delivery Notice <track@parcel-notify.example>", "Delivery attempt failed",
    "Your package could not be delivered. Reschedule: https://bit.ly/3xYzAbC")  # KNOWN HARD CASE (short smishing-style)


def write_csv() -> None:
    path = DATA / "sample_emails.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "label", "sender", "reply_to", "subject", "body", "spf", "dkim", "dmarc", "attachments"])
        for id_, label, sender, reply_to, subject, body, auth, attachments in ROWS:
            writer.writerow([id_, label, sender, reply_to, subject, body, *auth, attachments])
    print(f"wrote {path} ({len(ROWS)} rows)")


def _eml(name, headers, text, html=None, attachment=None, extra=None):
    msg = EmailMessage()
    for key, value in headers.items():
        msg[key] = value
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    if attachment:
        fname, data = attachment
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=fname)
    (EML_DIR / name).write_bytes(msg.as_bytes())


def write_eml_samples() -> None:
    EML_DIR.mkdir(parents=True, exist_ok=True)
    placeholder = b"HARMLESS PLACEHOLDER TEXT - this is not an executable."
    _eml("phishing_paypal_lookalike.eml", {
        "From": '"PayPal Support" <service@paypa1-secure.top>',
        "Reply-To": "paypal.resolution@gmail.com",
        "Return-Path": "<bounce@mailer-xyz.example>",
        "To": "victim@acme-corp.example",
        "Subject": "Your PayPal account has been limited - action required",
        "Date": "Mon, 05 Oct 2026 09:12:00 +0000",
        "Message-ID": "<20261005091200.1@paypa1-secure.top>",
        "Authentication-Results": "mx.acme-corp.example; spf=fail smtp.mailfrom=paypa1-secure.top; dkim=none; dmarc=fail",
    }, "We noticed unusual activity. Verify your account and confirm your password within 24 hours: "
       "http://paypa1-secure.top/login",
       html='<html><body><p>We noticed unusual activity on your account.</p><p>Verify your account and confirm your '
            'password within 24 hours.</p><p><a href="http://paypa1-secure.top/login">https://www.paypal.com/restore</a></p>'
            '</body></html>')
    _eml("phishing_invoice_exe.eml", {
        "From": "Accounts <billing@invoice-center.example>",
        "To": "finance@acme-corp.example",
        "Subject": "Unpaid invoice - final notice",
        "Date": "Tue, 06 Oct 2026 14:30:00 +0000",
        "Message-ID": "<20261006143000.7@invoice-center.example>",
        "Authentication-Results": "mx.acme-corp.example; spf=softfail; dkim=none; dmarc=none",
    }, "Your invoice is overdue. Open the attached invoice immediately to avoid legal action.",
       attachment=("invoice_8841.pdf.exe", placeholder))
    _eml("spam_lottery.eml", {
        "From": "Lottery Board <winner@global-lotto-claims.top>",
        "Reply-To": "claims.dept.2026@gmail.com",
        "To": "undisclosed-recipients:;",
        "Subject": "CONGRATULATIONS!!! YOU HAVE WON THE JACKPOT",
        "Date": "Wed, 07 Oct 2026 03:45:00 +0000",
        "Message-ID": "<20261007034500.3@global-lotto-claims.top>",
    }, "Dear Winner, you have won the international lottery jackpot of $1,800,000 USD! Claim your prize now - "
       "contact our claims officer immediately. Act now, limited time!!!")
    _eml("spam_pharmacy_html.eml", {
        "From": "Online Pharmacy <sales@cheap-meds-24.xyz>",
        "To": "someone@example.org",
        "Subject": "Cheap Viagra - no prescription - best price",
        "Date": "Wed, 07 Oct 2026 11:00:00 +0000",
        "Message-ID": "<20261007110000.9@cheap-meds-24.xyz>",
    }, "Cheap Viagra and Cialis. No prescription. Best price. Order now!",
       html='<html><body><h1>Online pharmacy</h1><p>Cheap Viagra and Cialis, no prescription, best price. '
            '<a href="http://cheap-meds-24.xyz/shop">Order now</a>!</p></body></html>')
    _eml("legitimate_meeting.eml", {
        "From": "Priya Sharma <priya.sharma@acme-corp.example>",
        "To": "team@acme-corp.example",
        "Subject": "Agenda for Thursday's planning meeting",
        "Date": "Thu, 08 Oct 2026 08:05:00 +0000",
        "Message-ID": "<20261008080500.2@acme-corp.example>",
        "Authentication-Results": "mx.acme-corp.example; spf=pass; dkim=pass; dmarc=pass",
    }, "Hi all,\n\nAttached to the calendar invite is the agenda for Thursday's planning meeting. Please add your "
       "items to the shared document beforehand.\n\nThanks,\nPriya")
    _eml("legitimate_newsletter.eml", {
        "From": "Cloud Weekly <news@cloudweekly.example>",
        "To": "subscriber@acme-corp.example",
        "Subject": "This week in cloud: 5 articles worth reading",
        "Date": "Fri, 09 Oct 2026 06:00:00 +0000",
        "Message-ID": "<20261009060000.5@cloudweekly.example>",
        "List-Unsubscribe": "<https://cloudweekly.example/unsubscribe>",
        "Authentication-Results": "mx.acme-corp.example; spf=pass; dkim=pass; dmarc=pass",
    }, "Here are this week's top stories: https://cloudweekly.example/issue/212",
       html='<html><body><p>Here are this week\'s top stories.</p><p><a href="https://cloudweekly.example/issue/212">'
            'Read the issue</a></p></body></html>')
    print(f"wrote 6 .eml samples to {EML_DIR}")


if __name__ == "__main__":
    DATA.mkdir(exist_ok=True)
    write_csv()
    write_eml_samples()
