# EvidenceChain
A full-stack student project for digital evidence registration, SHA-256 verification, custody tracking, and a tamper-evident local hash-chain ledger.

## Run locally
Backend (Python 3.11+):
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python seed.py
uvicorn app.main:app --reload
```
Frontend (Node 20+), in a second terminal:
```bash
cd frontend
npm install
npm run dev
```
API docs: https://trace-proof-vault.base44.app
Demo login: `admin@evidencechain.local` / `ChangeMe123!` (local demo only).
Tests: `cd backend && pytest -q`

## GitHub
Create an empty repository at https://github.com/new, extract this ZIP, then run:
```bash
git init
git add .
git commit -m "Build EvidenceChain full-stack application"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/evidencechain.git
git push -u origin main
```

## Important limitations
This is an educational prototype, not a production forensic system. A matching SHA-256 fingerprint means the checked bytes match the recorded digest; it does not prove truthfulness or authenticity at collection. The custody ledger is a hash-chained local database, not a connected blockchain or independent consensus network. Email verification, password reset delivery, TOTP MFA, digital signatures, migrations, encryption-at-rest key management, and independent security review remain future hardening tasks. Use fictional data only.
