"""
generate_dataset.py
--------------------
Builds a larger, more realistic training dataset for the phishing
detector than the original 280-sample version.

Why the old dataset caused problems:
- Only 280 samples, hand-written to be obviously phishing or obviously
  safe. Every phishing example contained words like "URGENT" or
  "verify now", and every safe example was casual small talk. The
  model could get 100% accuracy just by memorising a few trigger
  words, which does NOT generalise to real, messier messages.

What changed here:
- Far more samples (700+), built from templates with randomised
  variables (brand names, amounts, links, names) so the wording
  varies a lot instead of repeating a handful of fixed sentences.
- Deliberate overlap between the two classes: some LEGITIMATE
  messages use urgent language ("URGENT: submit your report by
  5pm") because real workplace messages do that too. Some PHISHING
  messages are calm and well-written with no urgency at all, because
  real attackers vary their tone. This forces the model to learn
  genuine patterns instead of a single keyword shortcut, and produces
  a more realistic (not artificially perfect) accuracy score.
"""

import pandas as pd
import random

random.seed(42)

brands = ["PayPal", "Amazon", "Netflix", "Apple", "Microsoft", "your bank",
          "Chase Bank", "DHL", "FedEx", "the IRS", "Instagram", "Facebook",
          "LinkedIn", "your university portal", "Zoom", "Dropbox"]

# Mostly realistic-looking domains (.com, .net) rather than obviously
# odd TLDs, since real phishing today mostly uses ordinary-looking
# domains. This stops the model from taking the shortcut of just
# checking the TLD instead of reading the message.
fake_domains = ["paypal-secure-verify.com", "amaz0n-account-help.com",
                "netflix-billinginfo.com", "apple-id-support.net",
                "secure-login-update.com", "account-verify-now.com",
                "bank-alert-confirm.com", "delivery-fee-pay.net",
                "irs-refund-claim.com", "paypa1.com", "chase-secure.net",
                "myaccount-support.com", "confirm-billing.net"]

real_domains = ["paypal.com", "amazon.com", "netflix.com", "apple.com",
                "chase.com", "dhl.com", "irs.gov", "instagram.com", "zoom.us"]

names = ["Sarah", "David", "Chioma", "James", "Amaka", "Michael", "Grace",
         "Tunde", "Aisha", "Peter", "the HR team", "the finance office"]

# ---------------------------------------------------------------------
# PHISHING TEMPLATES (label = 1)
# A mix of high-pressure classics AND calmer, more subtle attempts,
# so the model can't rely purely on "urgent" style keywords.
# ---------------------------------------------------------------------
phishing_templates = [
    "URGENT: Your {brand} account has been suspended. Verify immediately at http://{fake}/verify",
    "We noticed unusual activity on your {brand} account. Confirm your identity now: http://{fake}",
    "Your {brand} payment could not be processed. Update your billing details here: http://{fake}/billing",
    "Congratulations! You have won a ${amount} gift card. Claim it now at http://{fake}/claim",
    "{brand} Security Alert: Your password will expire in 24 hours. Reset here: http://{fake}/reset",
    "Dear customer, your {brand} account will be closed unless you verify your details at http://{fake}",
    "Your package from {brand} could not be delivered. Pay a ${amount} redelivery fee at http://{fake}",
    "Final notice: Your {brand} subscription has been charged ${amount}. Dispute the charge at http://{fake}",
    "Hi, this is {name} from {brand} support. We need you to confirm your login at http://{fake} to avoid suspension.",
    "Your tax refund of ${amount} is ready. Claim it before it expires at http://{fake}/refund",
    "We detected a login attempt from a new device on your {brand} account. If this wasn't you, secure it at http://{fake}",
    "Your {brand} invoice #{num} is overdue. Pay immediately to avoid penalty: http://{fake}/pay",
    "Action required: your {brand} storage is full. Upgrade now to avoid data loss: http://{fake}/upgrade",
    "{name}, I saw your resume online and have a job offer paying ${amount}/week. Send your bank details to get started: http://{fake}",
    "Your account has been flagged for review. Click here to avoid permanent suspension: http://{fake}",
    "Verify your {brand} account to continue using our services without interruption: http://{fake}/verify",
    "You have a new secure message from {brand}. View it here: http://{fake}/message",
    "Our records show your {brand} membership has expired. Renew now to keep your benefits: http://{fake}/renew",
    "Hello, I'm reaching out about your recent order. There's a small issue with delivery, please confirm your address again at http://{fake}",
    "As part of a routine security update, {brand} is asking all users to re-enter their login details at http://{fake}",
    "I'm {name} from IT. We're migrating systems this week, please log in here to keep your access: http://{fake}",
    "Your {brand} account password was changed. If this wasn't you, click here immediately: http://{fake}",
    "Reminder: your annual {brand} fee of ${amount} is due. Update your payment method: http://{fake}",
    "A refund of ${amount} has been issued to your {brand} account. Confirm receipt here: http://{fake}",
    "{name} shared a document with you on {brand}. Sign in to view: http://{fake}/doc",
    # Calmer, casual-toned phishing with no urgency words at all
    "Hey, quick one - we noticed a login from a new device on your {brand} account. If that wasn't you, just pop over to http://{fake} and lock it down.",
    "Hi there, your {brand} account details need a quick update, nothing serious. Here's the link: http://{fake}",
    "Just letting you know your {brand} card on file is expiring soon, update it whenever you get a chance: http://{fake}",
    "Thanks for your recent {brand} order! One small thing - we need you to confirm shipping details at http://{fake}",
    "Following up on your {brand} account - looks like there's a small billing mismatch, take a look here: http://{fake}",
    "Good afternoon, HR here. Please update your direct deposit info through this portal: http://{fake}/payroll",
    "Your {brand} rewards points are about to expire. Redeem them here: http://{fake}/rewards",
    "We're rolling out a new {brand} login system. Please re-authenticate at http://{fake} within 7 days.",
    # Bare credential-harvesting commands - no link, no brand, no
    # urgency keyword. These are common in real phishing/vishing/
    # smishing texts and were completely missing before, which is
    # why messages like "input your bank password now" slipped
    # through as SAFE.
    "Input your bank password now.",
    "Send me your card number and CVV so I can process this.",
    "Please reply with your PIN to confirm your identity.",
    "Type your online banking password here to continue.",
    "What's your one-time password? I need it to verify the transaction.",
    "Enter your social security number below to proceed.",
    "Share your login and password with me so I can fix your account.",
    "Give me your ATM PIN so I can help you reverse the charge.",
    "Text me your OTP code right now.",
    "I need your full card details, number, expiry, and CVV, to complete the order.",
    "Reply with your username and password to unlock your account.",
    "Confirm your identity by sending your date of birth and account number.",
    "Give me your card number and expiry date so I can process this.",
    "I need your account number and routing number right away.",
    "Send your debit card number and expiry date to complete the refund.",
    "What's your mother's maiden name and account PIN?",
    "Provide your full card details so we can verify the purchase.",
]

# ---------------------------------------------------------------------
# LEGITIMATE TEMPLATES (label = 0)
# Includes ordinary chat, business email AND some that borrow
# "urgent" or "verify" style language for genuinely normal reasons,
# so those words alone don't guarantee a phishing label.
# ---------------------------------------------------------------------
legitimate_templates = [
    "Hey, are we still meeting for lunch tomorrow?",
    "Your {brand} order has been delivered. Thanks for shopping with us.",
    "Please find attached the quarterly report for review.",
    "{name}, can you send me the notes from today's meeting?",
    "Reminder: team standup is at 9am tomorrow.",
    "Thanks for the update, I'll review it and get back to you by Friday.",
    "Your {brand} receipt for ${amount} is attached for your records.",
    "URGENT: please submit your timesheet by 5pm today, payroll closes tonight.",
    "Hi {name}, just checking in — did you get a chance to look at the draft?",
    "Your appointment with the dentist is confirmed for next Tuesday at 10am.",
    "{brand} order confirmation: your item will arrive within 3-5 business days.",
    "Can we reschedule our call to Thursday afternoon instead?",
    "Happy birthday! Hope you have a great day.",
    "The Wi-Fi password for the office has been updated, see IT for details.",
    "Your monthly statement from {brand} is now available in your account.",
    "{name} added a comment to the shared document, take a look when you can.",
    "Please review and sign the attached contract at your earliest convenience.",
    "Reminder from {brand}: your subscription renews next month at the current rate.",
    "Let's grab coffee sometime next week, I'm free Tuesday or Wednesday.",
    "Your flight booking with confirmation number {num} has been confirmed.",
    "The report you asked for is in the shared drive under Q3 documents.",
    "Verify your email address to complete your {brand} account setup (click the link we sent when you signed up on {brand}).",
    "Urgent heads up: the client meeting moved to 2pm, same room.",
    "Thanks for your payment of ${amount}, your invoice has been marked as paid.",
    "{name}, welcome to the team! Let me know if you need anything to get set up.",
    "Your package from {brand} is out for delivery and should arrive today.",
    "Just a reminder that the office will be closed on Monday for the holiday.",
    "I've updated the shared spreadsheet with the latest numbers, take a look.",
    "Great meeting today, I'll send the follow-up notes shortly.",
    "Your {brand} account statement is ready to view in your dashboard.",
    # Legitimate messages that borrow "scammy sounding" language for
    # genuine reasons, and legitimate messages that include real links
    "URGENT: server maintenance tonight at 11pm, please save your work and log off by then.",
    "Your {brand} order confirmation and tracking link: https://{real}/orders/track",
    "Please verify your shipping address is correct before we dispatch your {brand} order: https://{real}/account",
    "Reminder: your {brand} free trial ends in 3 days, you'll be charged ${amount} unless you cancel.",
    "Hi {name}, following up on the invoice - can you confirm payment went through on your end?",
    "Your card ending in 4321 was charged ${amount} at {brand}, reply STOP to dispute.",
    "Team, urgent request from the client - need the deck finalised by tonight, sorry for the short notice.",
    "This is a reminder that your password will expire in 7 days, you can update it anytime from Settings.",
    "Your {brand} security code is 483920, do not share this code with anyone.",
    "Hey, can you confirm your account details with me tomorrow so I can process your reimbursement?",
    "Final reminder: open enrollment for benefits closes Friday, log in to the HR portal to make changes.",
    "Your refund of ${amount} for the returned item has been processed and should appear in 3-5 days.",
    # Mentions of passwords/PINs in safe, non-solicitous contexts, so
    # the model learns the difference between a message ABOUT
    # credentials and a message ASKING for your credentials.
    "I reset my own password today, the new login page is much faster.",
    "Reminder: never share your PIN or password with anyone, including us.",
    "Your password was successfully updated. If this wasn't you, contact support through the official app.",
    "For security, we'll never ask you to send your password or card details by text or email.",
    "I forgot my Wi-Fi password again, can you remind me what it is for the office router?",
    "Tip: use a different password for every account and enable two-factor authentication.",
    "Your new employee badge and system password will be ready for pickup at HR on Monday.",
]

# ---------------------------------------------------------------------
# HAND-WRITTEN "HARD" EXAMPLES (not template-generated)
# These sit close to the decision boundary on purpose: overlapping
# vocabulary, similar sentence shape, ambiguous framing. Real phishing
# corpora always contain messages like this, and a model that can only
# handle obvious cases will fail in production. Including these is
# what keeps the reported metrics honest rather than inflated.
# ---------------------------------------------------------------------
hard_phishing = [
    "Hi, this is Grace from accounting. Can you send over your bank details again? I think we have the wrong ones on file for payroll.",
    "Quick question - are you the one who submitted a password reset request this morning? If not just let us know here: myaccount-support.com",
    "Hope you're doing well! I wanted to follow up on that invoice from last week, mind confirming the account number you'd like the refund sent to?",
    "Hey it's James from the office downstairs, I locked myself out of the shared drive, can you send me your login just this once so I can grab the file?",
    "Good morning, this is a routine check from IT support. Could you confirm your current password so we can migrate your profile to the new system?",
    "Saw you applied for the remote position last month, we'd like to move forward - just need your ID and banking info to set up payroll before the interview.",
    "Your delivery driver is outside but the address on file seems incomplete, can you confirm your full address and a contact number quickly?",
    "I'm helping a colleague recover access to their account, could you forward the verification code you just received by text?",
    "Just a heads up your subscription renewed, if that's a mistake you can request a refund by replying with your card's last 4 digits.",
    "Hi, following up from our call earlier - go ahead and send the wire transfer to the new account details I emailed you.",
    "We tried to reach you about a missed delivery, please confirm your details so we can reschedule the drop-off this week.",
    "This is your building manager, we need tenants to re-verify their unit access codes through the new portal this month.",
    "Input your bank password now.",
    "Send your PIN to confirm your identity.",
    "Reply with your card number and CVV now.",
    "Give me your card number and expiry date.",
    "I need your account number and routing number right away.",
]

hard_legitimate = [
    "Hi, this is Grace from accounting, following up on your expense report - looks like a couple of receipts are missing, can you resend when you get a chance?",
    "Quick question - did you mean to submit the form twice? Just checking before I process it.",
    "Hope you're doing well! Wanted to follow up on the invoice from last week, I think it's already been paid, let me double check.",
    "Hey it's James from downstairs, I left my badge at home, can you let me in through the side door?",
    "Good morning, this is IT support following up on your ticket, your laptop is ready for pickup at the help desk.",
    "Saw your application for the remote role, we'd like to schedule an interview, are you free Thursday afternoon?",
    "Your delivery driver left a note, the package is with the front desk for pickup.",
    "I'm helping a colleague get set up, could you point them to the onboarding checklist?",
    "Just a heads up your subscription renews next week at the usual rate, no action needed unless you want to change plans.",
    "Hi, following up from our call earlier, I've sent the meeting notes and next steps to the shared folder.",
    "We tried to reach you about your appointment, please call the clinic to reschedule at your convenience.",
    "This is your building manager, reminder that the parking garage will be closed for cleaning this Saturday.",
    "Never share your password with anyone, including us.",
    "I reset my own password today, much faster now.",
]

def fill(template):
    return template.format(
        brand=random.choice(brands),
        fake=random.choice(fake_domains),
        real=random.choice(real_domains),
        name=random.choice(names),
        amount=random.choice([50, 99, 150, 250, 500, 1000, 2500]),
        num=random.randint(1000, 99999),
    )

def build_class(templates, label, n):
    rows = []
    seen = set()
    attempts = 0
    while len(rows) < n and attempts < n * 20:
        attempts += 1
        text = fill(random.choice(templates))
        if text in seen:
            continue
        seen.add(text)
        rows.append({"text": text, "label": label})
    return rows

if __name__ == "__main__":
    phishing_rows = build_class(phishing_templates, 1, 380)
    legit_rows = build_class(legitimate_templates, 0, 380)

    # Duplicate the hard hand-written examples a few times (with tiny
    # punctuation variations) so they make up a meaningful share of
    # the dataset rather than being drowned out by the templates.
    hard_rows = []
    for text in hard_phishing:
        for variant in [text, text.rstrip(".") + ".", text.replace(",", "")]:
            hard_rows.append({"text": variant, "label": 1})
    for text in hard_legitimate:
        for variant in [text, text.rstrip(".") + ".", text.replace(",", "")]:
            hard_rows.append({"text": variant, "label": 0})

    data = phishing_rows + legit_rows + hard_rows
    df = pd.DataFrame(data)
    df = df.drop_duplicates(subset="text").reset_index(drop=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    df.to_csv("data/dataset.csv", index=False)
    print(f"Dataset created: {len(df)} samples "
          f"({(df['label']==1).sum()} phishing, {(df['label']==0).sum()} legitimate)")
