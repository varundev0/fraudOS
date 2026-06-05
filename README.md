# FraudOS

AI-native fraud investigation engine. Accepts a structured fraud alert and returns a detailed AI-generated investigation report using Claude.

## Phase 1: FastAPI Backend

### Setup

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # add your ANTHROPIC_API_KEY
```

### Run the server

```bash
cd FraudOS
uvicorn backend.main:app --reload
```

The API is available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### Run synthetic test cases

```bash
cd FraudOS
python -m backend.tests.test_engine
```

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | None | Server health + model info |
| GET | `/api/test-cases` | X-API-Key | List 5 synthetic fraud scenarios |
| POST | `/api/investigate` | X-API-Key | Investigate a fraud alert |

All authenticated endpoints require the header `X-API-Key: <FRAUDOS_API_KEY>`.

### Example request

```bash
curl -X POST http://localhost:8000/api/investigate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-change-in-production" \
  -d '{
    "alert": {
      "transaction_id": "TXN-001",
      "amount": 49800,
      "currency": "INR",
      "entity_data": {"account_holder": "Test User", "account_age_days": 30},
      "rule_trigger": "HIGH_AMOUNT",
      "alert_type": "UPI_FRAUD"
    }
  }'
```

### Project structure

```
FraudOS/
├── backend/
│   ├── main.py                  # FastAPI app
│   ├── models.py                # Pydantic models
│   ├── investigation/
│   │   ├── engine.py            # Claude-powered investigation
│   │   ├── prompts.py           # Injection-resistant prompt templates
│   │   └── pii_filter.py        # PII tokenization before Claude
│   └── tests/
│       ├── synthetic_alerts.py  # 5 Indian banking fraud scenarios
│       └── test_engine.py       # CLI test runner
├── .gitignore
└── README.md
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key | — |
| `FRAUDOS_API_KEY` | API key for this service | `dev-key-change-in-production` |
| `MODEL` | Claude model to use | `claude-opus-4-6` |
