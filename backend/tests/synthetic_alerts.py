"""Synthetic fraud alert scenarios for Indian banking context."""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import AlertType, FraudAlert


# 1. UPI fraud — small amount, new merchant, unusual hour (2:47 AM)
UPI_FRAUD_ALERT = FraudAlert(
    transaction_id="TXN-UPI-20240315-001",
    amount=4999.00,
    currency="INR",
    entity_data={
        "account_holder": "Rajesh Kumar",
        "account_number": "XXXXXXXX4821",
        "upi_id": "rajesh.k@okicici",
        "phone": "9876543210",
        "account_age_days": 12,
        "kyc_status": "MINIMAL",
        "device_id": "DEV-NEW-20240314",
        "ip_address": "103.45.67.89",
        "beneficiary_upi": "merchant.newshop@ybl",
        "beneficiary_name": "QuickShop Enterprises",
        "merchant_category": "UNKNOWN",
        "transaction_hour": 2,
        "previous_transactions_30d": 0,
    },
    rule_trigger="NEW_MERCHANT_NIGHT_TRANSACTION",
    alert_type=AlertType.UPI_FRAUD,
    merchant_id="MERCH-QSE-2024",
    timestamp=datetime(2024, 3, 15, 2, 47, 33, tzinfo=timezone.utc),
)

# 2. Card fraud — large international transaction, account dormant 14 months
CARD_FRAUD_ALERT = FraudAlert(
    transaction_id="TXN-CARD-20240315-002",
    amount=87500.00,
    currency="INR",
    entity_data={
        "account_holder": "Priya Sharma",
        "card_last4": "7743",
        "card_type": "VISA_DEBIT",
        "email": "priya.sharma@gmail.com",
        "account_age_days": 1820,
        "last_transaction_days_ago": 427,
        "transaction_country": "UAE",
        "transaction_city": "Dubai",
        "mcc": "5912",
        "merchant_name": "Al Baraka Electronics LLC",
        "card_present": False,
        "ip_country": "AE",
        "device_fingerprint": "UNKNOWN",
        "previous_international_txns": 0,
        "daily_limit_utilization_pct": 87.5,
    },
    rule_trigger="DORMANT_ACCOUNT_INTL_HIGH_VALUE",
    alert_type=AlertType.CARD_FRAUD,
    merchant_id="MERCH-ALBARAKA-UAE",
    timestamp=datetime(2024, 3, 15, 14, 22, 10, tzinfo=timezone.utc),
)

# 3. AML — smurfing pattern: 5 deposits just under ₹50,000 reporting threshold in 48 hours
AML_SMURF_ALERT = FraudAlert(
    transaction_id="TXN-AML-20240315-003",
    amount=49800.00,
    currency="INR",
    entity_data={
        "account_holder": "Amit Verma",
        "account_number": "XXXXXXXX9934",
        "account_age_days": 45,
        "occupation": "SELF_EMPLOYED",
        "kyc_level": "FULL",
        "recent_deposits_48h": [
            {"amount": 49500, "timestamp": "2024-03-13T10:15:00Z", "source": "CASH"},
            {"amount": 49200, "timestamp": "2024-03-13T14:30:00Z", "source": "CASH"},
            {"amount": 48900, "timestamp": "2024-03-14T09:00:00Z", "source": "CASH"},
            {"amount": 49750, "timestamp": "2024-03-14T16:45:00Z", "source": "CASH"},
            {"amount": 49800, "timestamp": "2024-03-15T11:00:00Z", "source": "CASH"},
        ],
        "total_48h_deposits": 247150,
        "avg_monthly_balance_prev_6m": 8200,
        "source_of_funds_declared": "BUSINESS_INCOME",
        "branch_city": "Mumbai",
        "structured_deposit_flag": True,
    },
    rule_trigger="STRUCTURED_DEPOSITS_BELOW_THRESHOLD",
    alert_type=AlertType.AML,
    timestamp=datetime(2024, 3, 15, 11, 0, 0, tzinfo=timezone.utc),
)

# 4. Account takeover — device change followed immediately by high-value NEFT transfer
ACCOUNT_TAKEOVER_ALERT = FraudAlert(
    transaction_id="TXN-ATO-20240315-004",
    amount=250000.00,
    currency="INR",
    entity_data={
        "account_holder": "Sunita Patel",
        "account_number": "XXXXXXXX1157",
        "email": "sunita.patel@yahoo.co.in",
        "phone": "9845678901",
        "account_age_days": 2190,
        "device_changed_minutes_ago": 8,
        "previous_device_id": "DEV-SUNITA-IPHONE12-2022",
        "new_device_id": "DEV-UNKNOWN-ANDROID-2024",
        "new_device_ip": "45.123.78.90",
        "ip_location": "Hyderabad",
        "usual_login_city": "Pune",
        "login_time": "2024-03-15T07:14:00Z",
        "transfer_initiated_time": "2024-03-15T07:22:00Z",
        "beneficiary_name": "Rashid Ali Khan",
        "beneficiary_account": "XXXXXXXX4412",
        "beneficiary_ifsc": "HDFC0002341",
        "beneficiary_added_minutes_ago": 3,
        "transfer_type": "NEFT",
        "otp_delivery_method": "SMS",
    },
    rule_trigger="NEW_DEVICE_IMMEDIATE_HIGH_VALUE_TRANSFER",
    alert_type=AlertType.ACCOUNT_TAKEOVER,
    timestamp=datetime(2024, 3, 15, 7, 22, 45, tzinfo=timezone.utc),
)

# 5. Synthetic identity — new account, rapid credit utilization within 30 days
SYNTHETIC_IDENTITY_ALERT = FraudAlert(
    transaction_id="TXN-SYN-20240315-005",
    amount=95000.00,
    currency="INR",
    entity_data={
        "account_holder": "Vikram Singh Rathore",
        "account_number": "XXXXXXXX6623",
        "phone": "8800123456",
        "email": "vikram.s.rathore2024@outlook.com",
        "account_age_days": 28,
        "credit_limit": 100000,
        "current_utilization_pct": 95.0,
        "credit_score": 742,
        "credit_bureau_age_months": 2,
        "num_credit_inquiries_90d": 7,
        "address": "Flat 403, Suncity Apartments, Sector 18, Gurugram",
        "address_verification_status": "UNVERIFIED",
        "employer": "TechNova Solutions Pvt Ltd",
        "employer_verification_status": "UNVERIFIED",
        "aadhaar_linked": False,
        "pan_linked": True,
        "recent_transactions": [
            {"merchant": "Vijay Sales Electronics", "amount": 35000, "days_ago": 5},
            {"merchant": "Nykaa Online", "amount": 18000, "days_ago": 8},
            {"merchant": "Croma Retail", "amount": 42000, "days_ago": 15},
        ],
        "cash_advance_amount": 95000,
        "cash_advance_fee_waiver_requested": True,
    },
    rule_trigger="RAPID_CREDIT_UTILIZATION_NEW_ACCOUNT",
    alert_type=AlertType.SYNTHETIC_IDENTITY,
    timestamp=datetime(2024, 3, 15, 16, 5, 20, tzinfo=timezone.utc),
)


SYNTHETIC_ALERTS: list[FraudAlert] = [
    UPI_FRAUD_ALERT,
    CARD_FRAUD_ALERT,
    AML_SMURF_ALERT,
    ACCOUNT_TAKEOVER_ALERT,
    SYNTHETIC_IDENTITY_ALERT,
]
