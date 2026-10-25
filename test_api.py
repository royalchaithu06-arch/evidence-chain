import os
os.environ["DATABASE_URL"]="sqlite:///./test_evidencechain.db"
from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
def test_root():
 r=client.get("/");assert r.status_code==200 and r.json()["name"]=="EvidenceChain API"
def test_auth_required():
 assert client.get("/api/dashboard").status_code==401
def test_register_and_login():
 email="test-evidencechain@example.com"
 client.post("/api/auth/register",json={"name":"Test Student","email":email,"password":"LongPassword123!","terms_accepted":True})
 r=client.post("/api/auth/login",json={"email":email,"password":"LongPassword123!"})
 assert r.status_code==200 and "token" in r.json()
 assert client.get("/api/dashboard",headers={"Authorization":"Bearer "+r.json()["token"]}).status_code==200
