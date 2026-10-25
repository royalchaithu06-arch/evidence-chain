import hashlib,json,secrets
from datetime import datetime,timezone
from .models import CustodyEvent
GENESIS="GENESIS"
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def digest(x):return hashlib.sha256(canon(x).encode()).hexdigest()
def append(db,eid,caseid,action,actor,reason="",recipient=None):
 last=db.query(CustodyEvent).order_by(CustodyEvent.id.desc()).first();prev=last.event_hash if last else GENESIS
 p={"event_id":"EV-"+secrets.token_hex(6).upper(),"evidence_id":eid,"case_id":caseid,"action":action,"actor_id":actor,"recipient_id":recipient,"reason":reason[:2000],"timestamp":datetime.now(timezone.utc).isoformat(),"previous_hash":prev,"canonicalization":"json-sortkeys-compact-v1"}
 e=CustodyEvent(**p,payload_json=canon(p),event_hash=digest(p));db.add(e);db.flush();return e
def validate(db):
 rows=db.query(CustodyEvent).order_by(CustodyEvent.id.asc()).all();prev=GENESIS
 for e in rows:
  try:p=json.loads(e.payload_json)
  except:return {"valid":False,"failed_event_id":e.event_id,"reason":"Invalid payload JSON","checked":len(rows)}
  if e.previous_hash!=prev or p.get("previous_hash")!=prev:return {"valid":False,"failed_event_id":e.event_id,"reason":"Previous-event hash mismatch","checked":len(rows)}
  if digest(p)!=e.event_hash:return {"valid":False,"failed_event_id":e.event_id,"reason":"Event hash mismatch","checked":len(rows)}
  prev=e.event_hash
 return {"valid":True,"failed_event_id":None,"reason":"All event hashes validate","checked":len(rows),"head_hash":prev}
