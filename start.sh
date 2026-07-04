#!/bin/bash
# FraudOS local dev startup script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$SCRIPT_DIR/backend"
FRONTEND="$SCRIPT_DIR/frontend"

echo "=== FraudOS Dev Startup ==="

# ── PostgreSQL ────────────────────────────────────────────────────────────────
echo ""
echo "▶ Checking PostgreSQL..."
if command -v brew &>/dev/null && brew services list | grep -q postgresql; then
  brew services start postgresql@14 2>/dev/null || brew services start postgresql 2>/dev/null || true
elif command -v pg_ctl &>/dev/null; then
  pg_ctl status &>/dev/null || pg_ctl start &>/dev/null || true
fi

# Wait for postgres to be ready
for i in {1..10}; do
  pg_isready -q 2>/dev/null && break
  sleep 1
done

if pg_isready -q 2>/dev/null; then
  echo "  ✓ PostgreSQL is running"
  # Create DB if it doesn't exist
  psql -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw fraudos \
    || createdb fraudos 2>/dev/null && echo "  ✓ Created 'fraudos' database" \
    || echo "  ✓ 'fraudos' database already exists"
else
  echo "  ✗ PostgreSQL not found. Install with: brew install postgresql@14"
  echo "    Then run: brew services start postgresql@14 && createdb fraudos"
  exit 1
fi

# ── Backend ───────────────────────────────────────────────────────────────────
echo ""
echo "▶ Starting backend (FastAPI on :8000)..."
cd "$BACKEND"

# Create venv if needed
if [ ! -d ".venv" ]; then
  echo "  Creating virtualenv..."
  python3 -m venv .venv
fi

source .venv/bin/activate

# Install deps if needed
pip install -q -r requirements.txt

# Start backend in background (run from project root — uses relative imports)
cd "$SCRIPT_DIR"
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo "  ✓ Backend PID: $BACKEND_PID"

# ── Frontend ──────────────────────────────────────────────────────────────────
echo ""
echo "▶ Starting frontend (Vite on :5173)..."
cd "$FRONTEND"

if [ ! -d "node_modules" ]; then
  echo "  Installing npm packages..."
  npm install
fi

npm run dev &
FRONTEND_PID=$!
echo "  ✓ Frontend PID: $FRONTEND_PID"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "==========================================="
echo "  Backend:  http://localhost:8000"
echo "  Frontend: http://localhost:5173"
echo "  API docs: http://localhost:8000/docs"
echo "==========================================="
echo ""
echo "Press Ctrl+C to stop both servers."

# Wait and cleanup on exit
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
