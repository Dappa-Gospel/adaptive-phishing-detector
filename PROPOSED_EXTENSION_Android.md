# Proposed Extension: Android Notification-Based Live Detection

*(Not implemented — proposed as future work in the project report)*

## Motivation

The current system requires a user to manually copy and paste a
suspicious message into the web interface. In real-world use,
phishing attacks most often arrive as push notifications on a phone
(SMS, WhatsApp, Telegram) before the user has consciously decided
anything is suspicious. A live, on-device extension would move
detection to the moment of arrival rather than requiring the user to
already suspect something is wrong.

## Why this can't fully cover every messaging app

- **WhatsApp, Telegram, and iMessage are end-to-end encrypted** and
  do not expose a public API for a third-party app to read a
  personal user's incoming messages in real time. This is a
  deliberate privacy/security design decision by those platforms,
  not a technical gap that can be engineered around.
- **iOS restricts inter-app access** to notification content almost
  entirely, so this architecture is realistically Android-only.
- **Android is more open**, via the `NotificationListenerService`
  API, which is a legitimate, user-consented Android feature that
  reads the *text shown in a notification* (not the app's internal
  encrypted data). This is the same mechanism real apps like
  Truecaller and various spam-blocking apps use.

## Proposed architecture

1. **New message arrives** on the phone from any app (WhatsApp, SMS,
   Telegram, email, etc.), triggering a system notification as
   normal.
2. **Notification Listener Service** — a small Android companion
   app, after the user explicitly grants "Notification access" in
   Settings, receives the notification's text content as it posts.
   No message content is read outside of what already appears in the
   notification itself.
3. **Local classifier API** — the notification text is sent to a
   lightweight Flask/FastAPI server wrapping the existing trained
   Naive Bayes model and hybrid rule logic (`classifier.py`). This
   server could run locally on the same device/network for privacy,
   or on a small cloud instance if remote access is needed.
4. **Verdict returned** — PHISHING or SAFE, using the exact same
   decision logic already validated in this project (99%+ accuracy on
   the test set).
5. **User notified** — if flagged, the phone shows an alert
   notification with the verdict and reasons. Critically, the app
   never blocks, deletes, or hides the original message — it only
   informs. The user makes the final call whether to proceed, which
   directly satisfies the "user decides" requirement from the
   original brief.

## Technology stack

| Component | Technology |
|---|---|
| Companion app | Kotlin, Android `NotificationListenerService` |
| Communication | HTTP request from app to local API (Retrofit or OkHttp) |
| Classifier backend | Flask/FastAPI wrapping `classifier.py` (already built) |
| Alerting | Android system notification (`NotificationCompat`) |

## Known limitations (worth stating explicitly in the report)

- Android-only; no equivalent is possible on iOS without Apple's
  cooperation (there is no such official mechanism today).
- Requires the user to manually grant notification access — this is
  a one-time setup step, not automatic, by Android's design.
- Distributing this publicly via the Play Store has additional policy
  requirements around notification-reading apps, since the permission
  is powerful; this would need to be addressed for real deployment
  beyond a personal/demo build.
- Message text arrives only in whatever form the notification itself
  shows (which is sometimes truncated), not the full original
  message body — a genuine trade-off between privacy/simplicity and
  completeness.

## Why this is left as future work rather than implemented

Building a native Android app is a substantial, separate skill set
(Kotlin/Android SDK) from the Python/ML work in the core project, and
would meaningfully expand scope beyond a single final-year project
timeline. It is included here to demonstrate awareness of how the
system would need to evolve for real-world deployment, and to show
the architectural reasoning behind that evolution — which is exactly
what a "proposed future work" section in a project report is meant to
convey.
