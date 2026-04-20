"""
Training script for SafeTrace models.

Generates synthetic training data, trains classifiers, and persists
them to the models/ directory for use by the scanners.

Run:
    safetrace train
    python -m safetrace.train
"""

import logging
import os
import random
from typing import List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score

from safetrace.config import (
    MODELS_DIR,
    URL_MODEL_PATH,
    EMAIL_MODEL_PATH,
    EMAIL_VECTORIZER_PATH,
)
from safetrace.core.feature_extractor import extract_url_feature_vector, get_feature_names

logger = logging.getLogger("safetrace.train")


# ============================================================
# Synthetic URL Dataset
# ============================================================

SAFE_URLS = [
    "https://www.google.com",
    "https://www.github.com/explore",
    "https://stackoverflow.com/questions",
    "https://en.wikipedia.org/wiki/Python",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://docs.python.org/3/library/json.html",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.reddit.com/r/programming/",
    "https://www.linkedin.com/in/example/",
    "https://www.nytimes.com/2024/news/article",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://www.bbc.com/news/technology",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone/",
    "https://mail.google.com/mail/inbox",
    "https://www.netflix.com/browse",
    "https://www.spotify.com/premium/",
    "https://www.dropbox.com/home",
    "https://www.medium.com/@user/article",
    "https://www.notion.so/workspace",
    "https://www.figma.com/file/abc123",
    "https://www.slack.com/intl/en-us/",
    "https://www.zoom.us/j/123456789",
    "https://www.twitch.tv/directory",
    "https://www.instagram.com/explore/",
    "https://www.twitter.com/home",
    "https://www.facebook.com/events/",
    "https://www.pinterest.com/ideas/",
    "https://www.quora.com/topic/Science",
    "https://www.coursera.org/courses",
    "https://www.udemy.com/courses/development/",
    "https://www.khanacademy.org/math",
    "https://www.npmjs.com/package/express",
    "https://pypi.org/project/requests/",
    "https://hub.docker.com/_/python",
    "https://www.cloudflare.com/learning/",
    "https://aws.amazon.com/s3/",
    "https://cloud.google.com/products",
    "https://azure.microsoft.com/en-us/",
    "https://www.heroku.com/platform",
]

PHISHING_URLS = [
    "http://fake-login.xyz/verify-account",
    "http://192.168.1.1/login/secure-update",
    "http://paypal-secure-login.tk/confirm",
    "http://amaz0n.account-verify.ml/signin",
    "http://g00gle.com-login.cf/update-info",
    "http://free-iphone-winner.ga/claim-prize",
    "http://banking-secure-alert.top/urgent",
    "http://micr0soft-verify.buzz/account",
    "http://apple-id-confirm.xyz/login",
    "http://netflix-update.pw/billing",
    "http://secure-ebay-login.work/verify",
    "http://lucky-winner-prize.club/click",
    "http://account-suspended-verify.info/login",
    "http://192.168.0.100/admin/signin",
    "http://verify-your-paypal.ru/update",
    "http://facebook-login-alert.cn/confirm",
    "http://urgent-account-verify.gq/secure",
    "http://signin-update-banking.xyz/alert",
    "http://free-gift-click-now.tk/winner",
    "http://your-account-confirm.ml/prize",
    "http://login-verify-update.ga/secure",
    "http://click-here-free.cf/lucky",
    "http://banking-alert-urgent.top/suspend",
    "http://paypal-confirm-secure.buzz/login",
    "http://ebay-signin-verify.work/account",
    "http://192.0.0.1/phishing/page@fake",
    "http://verify-account-now.xyz/login?user=admin&pass=hack",
    "http://secure-banking-login.tk/update-confirm-verify",
    "http://free-prize-winner-click.ml/claim-now-urgent",
    "http://fake-microsoft-alert.ga/signin-update-secure",
    "http://account-login-confirm.cf/verify-banking-alert",
    "http://urgent-suspend-account.gq/click-free-prize",
    "http://login-verify.xyz/secure-update-confirm-banking",
    "http://click-free-winner.top/lucky-prize-claim",
    "http://alert-suspend-urgent.buzz/verify-account-login",
    "http://confirm-signin-update.work/secure-banking-ebay",
    "http://prize-click-free.info/winner-lucky-claim",
    "http://verify-update-confirm.ru/login-secure-alert",
    "http://suspend-account-urgent.cn/confirm-verify-signin",
    "http://banking-login-alert.pw/update-secure-verify",
]


# ============================================================
# Synthetic Email / Text Dataset
# ============================================================

SAFE_EMAILS = [
    "Hi team, the meeting has been moved to 3pm tomorrow. Please update your calendars.",
    "Here is the quarterly report for Q3. Let me know if you have questions.",
    "Thanks for your purchase! Your order #12345 has been shipped.",
    "Reminder: office will be closed on Monday for the holiday.",
    "Welcome to the team! Your onboarding documents are attached.",
    "The code review for PR #892 is ready. Please take a look when you get a chance.",
    "Just following up on our conversation from last week about the project timeline.",
    "Hi, I wanted to share this interesting article about machine learning trends.",
    "Your subscription has been renewed. No action is needed.",
    "Meeting notes from today's standup are available in the shared drive.",
    "The new release is scheduled for next Friday. Here's the changelog.",
    "Happy birthday! Hope you have a great day.",
    "Attached is the invoice for last month's services. Payment is due in 30 days.",
    "The server migration is complete. All services are running normally.",
    "Please review the updated documentation before the next sprint.",
    "Your flight confirmation: Departure at 8:00 AM, Gate B12.",
    "The team lunch is scheduled for Thursday at noon. RSVP here.",
    "Thank you for attending the webinar. Here are the slides.",
    "The build passed all tests. Ready for merge.",
    "Congratulations on completing the training course!",
    "Our office hours are Monday through Friday, 9 AM to 5 PM.",
    "Here's the link to the shared Google Doc for our project notes.",
    "The weekly newsletter is here. Check the latest updates.",
    "Your package has been delivered. Thank you for shopping with us.",
    "Reminder to submit your timesheet by end of day Friday.",
]

PHISHING_EMAILS = [
    "URGENT: Your account has been compromised. Verify your identity immediately or your account will be suspended.",
    "Dear customer, we detected unauthorized access to your account. Enter your password to confirm your identity now.",
    "Congratulations! You have won a $1,000,000 prize. Click here to claim your prize immediately!",
    "ALERT: Your bank account will be locked. Update your information within 24 hours or face permanent suspension.",
    "Dear valued customer, failure to verify your account will result in permanent disabling. Act now!",
    "SECURITY ALERT: Unauthorized access detected. Confirm your account details including your credit card number.",
    "You have been selected as winner of our annual lottery! Claim your inheritance now. Limited time offer!",
    "Dear user, your social security number needs verification. Enter your password and bank account details.",
    "URGENT: Account will be suspended in 24 hours. Verify your identity by clicking the link below immediately.",
    "Official notification from the management team: Update your information or your account will be permanently disabled.",
    "Free gift awaiting! Confirm your account to receive a million dollars. Don't delay, act now!",
    "Your account has been compromised. The support team requires you to enter your password right away.",
    "Dear valued user, this is an urgent security alert. Failure to verify will result in account suspension.",
    "From the desk of the management team: Your account shows unauthorized access. Confirm immediately.",
    "HURRY! Limited time to claim your free gift. You have won a special prize as our lucky winner!",
    "Dear customer, deadline approaching! Verify your identity and update your information to avoid suspension.",
    "Your credit card number is needed for verification. This is an official notification. Act now!",
    "Account suspended due to unauthorized access. Enter your password and social security to reactivate.",
    "Congratulations! You are our selected winner. Claim your million dollars prize before the deadline expires.",
    "URGENT security alert from the support team. Your account will be locked. Confirm your account right away.",
    "Dear user, we need you to verify your bank account details immediately to prevent permanent suspension.",
    "Free gift! You have been selected as winner of our prize draw. Click to claim your inheritance now.",
    "This is an official notification: failure to update your information will result in your account being permanently disabled.",
    "ALERT: Unauthorized access to your bank account. Enter your credit card number to verify your identity.",
    "Don't delay! Your account has been compromised. The management team urgently requires your password.",
]


def _generate_url_dataset() -> Tuple[np.ndarray, np.ndarray]:
    """Build feature matrix and labels from the URL lists.

    Returns:
        X: Feature matrix (n_samples, n_features).
        y: Label array (0 = safe, 1 = phishing).
    """
    urls = SAFE_URLS + PHISHING_URLS
    labels = [0] * len(SAFE_URLS) + [1] * len(PHISHING_URLS)

    feature_vectors = []
    valid_labels = []

    for url, label in zip(urls, labels):
        try:
            vec = extract_url_feature_vector(url)
            feature_vectors.append(vec)
            valid_labels.append(label)
        except ValueError:
            logger.warning("Skipping invalid URL during training: %s", url)
            continue

    return np.array(feature_vectors), np.array(valid_labels)


def _generate_email_dataset() -> Tuple[List[str], List[int]]:
    """Build text corpus and labels from the email lists.

    Returns:
        texts: List of raw text samples.
        labels: List of labels (0 = safe, 1 = phishing).
    """
    texts = SAFE_EMAILS + PHISHING_EMAILS
    labels = [0] * len(SAFE_EMAILS) + [1] * len(PHISHING_EMAILS)
    return texts, labels


def train_url_model() -> None:
    """Train and save the URL phishing classifier."""
    logger.info("=" * 55)
    logger.info("  Training URL scanner model")
    logger.info("=" * 55)

    X, y = _generate_url_dataset()
    logger.info(
        "  Dataset: %d samples (%d safe, %d phishing)",
        len(X), int((y == 0).sum()), int((y == 1).sum()),
    )
    logger.info("  Features: %d — %s", len(get_feature_names()), get_feature_names())

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )

    # Cross-validation
    scores = cross_val_score(model, X, y, cv=min(5, len(X)), scoring="accuracy")
    logger.info("  Cross-val accuracy: %.3f (+/- %.3f)", scores.mean(), scores.std())

    # Train on full dataset
    model.fit(X, y)

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(model, URL_MODEL_PATH)
    logger.info("  ✅ Model saved → %s", URL_MODEL_PATH)


def train_email_model() -> None:
    """Train and save the email phishing classifier."""
    logger.info("=" * 55)
    logger.info("  Training email scanner model")
    logger.info("=" * 55)

    texts, labels = _generate_email_dataset()
    y = np.array(labels)
    logger.info(
        "  Dataset: %d samples (%d safe, %d phishing)",
        len(texts), int((y == 0).sum()), int((y == 1).sum()),
    )

    vectorizer = TfidfVectorizer(
        max_features=500,
        stop_words="english",
        ngram_range=(1, 2),
    )
    X = vectorizer.fit_transform(texts)
    logger.info("  TF-IDF features: %d", X.shape[1])

    model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        class_weight="balanced",
    )

    scores = cross_val_score(model, X, y, cv=min(5, len(texts)), scoring="accuracy")
    logger.info("  Cross-val accuracy: %.3f (+/- %.3f)", scores.mean(), scores.std())

    model.fit(X, y)

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(model, EMAIL_MODEL_PATH)
    joblib.dump(vectorizer, EMAIL_VECTORIZER_PATH)
    logger.info("  ✅ Model saved → %s", EMAIL_MODEL_PATH)
    logger.info("  ✅ Vectorizer saved → %s", EMAIL_VECTORIZER_PATH)


def main() -> None:
    """Train all SafeTrace models."""
    # Ensure logging is visible during standalone training
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s | %(message)s",
    )

    logger.info("")
    logger.info("  🔐 SafeTrace Model Training")
    logger.info("")

    random.seed(42)
    np.random.seed(42)

    train_url_model()
    train_email_model()

    logger.info("=" * 55)
    logger.info("  ✅ All models trained successfully!")
    logger.info("  You can now use: safetrace url <url>")
    logger.info("                   safetrace email <text>")
    logger.info("=" * 55)


if __name__ == "__main__":
    main()
