import os,hashlib,secrets,csv,io,json
from pathlib import Path
from datetime import datetime,timezone
from fastapi import FastAPI,Depends,HTTPException,UploadFile,File,Form,Response,Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel,EmailStr,Field
from sqlalchemy.orm import Session
from sqlalchemy import or_
from .database import Base,engine,get_db
from .models import User,SessionToken,Evidence,CustodyEvent,VerificationRun,MentorProgress
from .security import pwd,new_session,current_user,require,h
from .ledger import append,validate
Base.metadata.create_all(bind=engine)
app=FastAPI(title="EvidenceChain API",version="1.0.0",description="Student prototype: local hash-chained ledger, not connected blockchain.")
app.add_middleware(CORSMiddleware,allow_origins=os.getenv("CORS_ORIGINS","http://localhost:5173").split(","),allow_credentials=False,allow_methods=["GET","POST"],allow_headers=["Authorization","Content-Type"])
STORE=Path(__file__).resolve().parent.parent/"private_storage";STORE.mkdir(parents=True,exist_ok=True)
MAX=int(os.getenv("MAX_UPLOAD_MB","20"))*1024*1024
class Reg(BaseModel):
 name:str=Field(min_length=2,max_length=120);email:EmailStr;password:str=Field(min_length=10,max_length=72);terms_accepted:bool
class Login(BaseModel): email:EmailStr;password:str
class Progress(BaseModel): lesson_key:str;completed:bool=True
def utc():return datetime.now(timezone.utc).isoformat()
def out(e):return {"evidence_id":e.evidence_id,"case_id":e.case_id,"type":e.evidence_type,"filename":e.filename,"description":e.description,"classification":e.classification,"collected_at":e.collected_at,"collector_id":e.collector_id,"sha256":e.sha256,"file_size":e.file_size,"content_type":e.content_type,"current_custodian_id":e.current_custodian_id}
def allowed(e,u):return u.role in {"Administrator","Auditor","Investigator"} or u.id in {e.collector_id,e.current_custodian_id}
@app.get("/")
def root():return {"name":"EvidenceChain API","docs":"/docs","mode":"LOCAL DEMO","ledger":"local hash chain, not blockchain consensus"}
@app.post("/api/auth/register")
def register(p:Reg,db:Session=Depends(get_db)):
 if not p.terms_accepted:raise HTTPException(400,"Terms acceptance required")
 email=p.email.lower()
 if db.query(User).filter_by(email=email).first():raise HTTPException(409,"Unable to create account with these details")
 u=User(name=p.name.strip(),email=email,password_hash=pwd.hash(p.password),role="Evidence Collector");db.add(u);db.commit();db.refresh(u)
 return {"token":new_session(db,u),"user":{"id":u.id,"name":u.name,"email":u.email,"role":u.role}}
@app.post("/api/auth/login")
def login(p:Login,db:Session=Depends(get_db)):
 u=db.query(User).filter_by(email=p.email.lower()).first()
 if not u or not pwd.verify(p.password,u.password_hash):raise HTTPException(401,"Invalid email or password")
 return {"token":new_session(db,u),"user":{"id":u.id,"name":u.name,"email":u.email,"role":u.role}}
@app.post("/api/auth/logout")
def logout(u:User=Depends(current_user),db:Session=Depends(get_db),c=Depends(__import__("fastapi.security",fromlist=["HTTPBearer"]).HTTPBearer())):
 s=db.query(SessionToken).filter_by(token_hash=h(c.credentials),revoked=False).first()
 if s:s.revoked=True;db.commit()
 return {"ok":True}
@app.get("/api/me")
def me(u:User=Depends(current_user)):return {"id":u.id,"name":u.name,"email":u.email,"role":u.role}
@app.get("/api/dashboard")
def dashboard(u:User=Depends(current_user),db:Session=Depends(get_db)):
 es=db.query(Evidence).all();vs=db.query(VerificationRun).all();events=db.query(CustodyEvent).order_by(CustodyEvent.id.desc()).limit(10).all()
 return {"demo":True,"evidence_count":len(es),"matches":sum(x.result=="MATCH" for x in vs),"mismatches":sum(x.result=="MISMATCH" for x in vs),"events":[{"event_id":x.event_id,"evidence_id":x.evidence_id,"action":x.action,"timestamp":x.timestamp} for x in events],"evidence":[out(x) for x in es[:8]]}
@app.post("/api/evidence")
async def register_evidence(case_id:str=Form(...),evidence_type:str=Form(...),description:str=Form(""),classification:str=Form("Internal"),collected_at:str=Form(...),file:UploadFile=File(...),u:User=Depends(current_user),db:Session=Depends(get_db)):
 if evidence_type not in {"Document","Image","Log","Video","Audio","Other"}:raise HTTPException(422,"Unsupported evidence type")
 sha=hashlib.sha256();size=0;storage=secrets.token_hex(24);path=STORE/storage
 with path.open("wb") as f:
  while True:
   chunk=await file.read(1024*1024)
   if not chunk:break
   size+=len(chunk)
   if size>MAX:
    f.close();path.unlink(missing_ok=True);raise HTTPException(413,"File exceeds configured upload limit")
   sha.update(chunk);f.write(chunk)
 if size==0:path.unlink(missing_ok=True);raise HTTPException(400,"Empty files cannot be registered")
 eid="EC-"+secrets.token_hex(6).upper()
 e=Evidence(evidence_id=eid,case_id=case_id[:80],evidence_type=evidence_type,filename=Path(file.filename or "evidence.bin").name[:255],description=description[:5000],classification=classification[:40],collected_at=collected_at,collector_id=u.id,sha256=sha.hexdigest(),file_size=size,content_type=(file.content_type or "application/octet-stream")[:120],storage_name=storage,current_custodian_id=u.id)
 db.add(e);db.flush();append(db,eid,e.case_id,"EVIDENCE_REGISTERED",u.id,"Backend-computed SHA-256 fingerprint");db.commit();db.refresh(e)
 return {"evidence":out(e),"receipt":{"evidence_id":eid,"sha256":e.sha256,"collected_at":collected_at,"notice":"Hash match proves byte consistency only, not authenticity or truthfulness."}}
@app.get("/api/evidence")
def list_evidence(q:str="",case_id:str="",limit:int=Query(100,ge=1,le=200),offset:int=Query(0,ge=0),u:User=Depends(current_user),db:Session=Depends(get_db)):
 qy=db.query(Evidence)
 if q:qy=qy.filter(or_(Evidence.evidence_id.ilike(f"%{q[:80]}%"),Evidence.filename.ilike(f"%{q[:200]}%")))
 if case_id:qy=qy.filter_by(case_id=case_id)
 return {"items":[out(e) for e in qy.order_by(Evidence.id.desc()).offset(offset).limit(limit).all() if allowed(e,u)],"limit":limit,"offset":offset}
@app.get("/api/evidence/{eid}")
def detail(eid:str,u:User=Depends(current_user),db:Session=Depends(get_db)):
 e=db.query(Evidence).filter_by(evidence_id=eid).first()
 if not e or not allowed(e,u):raise HTTPException(404,"Evidence not found")
 return out(e)
@app.get("/api/evidence/{eid}/download")
def download(eid:str,u:User=Depends(current_user),db:Session=Depends(get_db)):
 e=db.query(Evidence).filter_by(evidence_id=eid).first()
 if not e or not allowed(e,u):raise HTTPException(404,"Evidence not found")
 p=STORE/e.storage_name
 if not p.is_file():raise HTTPException(503,"Stored evidence unavailable")
 return Response(p.read_bytes(),media_type=e.content_type,headers={"Content-Disposition":f'attachment; filename="{e.filename.replace(chr(34),"")}"',"X-Content-Type-Options":"nosniff"})
@app.post("/api/evidence/{eid}/verify")
async def verify(eid:str,file:UploadFile|None=File(None),u:User=Depends(current_user),db:Session=Depends(get_db)):
 e=db.query(Evidence).filter_by(evidence_id=eid).first()
 if not e or not allowed(e,u):raise HTTPException(404,"Evidence not found")
 sha=hashlib.sha256();size=0;detail_text=""
 try:
  if file:
   while True:
    chunk=await file.read(1024*1024)
    if not chunk:break
    size+=len(chunk)
    if size>MAX:raise HTTPException(413,"Verification file too large")
    sha.update(chunk)
  else:
   p=STORE/e.storage_name
   if not p.is_file():raise OSError()
   with p.open("rb") as f:
    for chunk in iter(lambda:f.read(1024*1024),b""):sha.update(chunk)
  computed=sha.hexdigest();result="MATCH" if computed==e.sha256 else "MISMATCH";detail_text="Checked bytes match recorded fingerprint." if result=="MATCH" else "Checked bytes differ. Original digest was not changed."
 except HTTPException:raise
 except Exception:computed="";result="ERROR";detail_text="File unavailable; verification could not be completed."
 stamp=utc();db.add(VerificationRun(evidence_id=eid,actor_id=u.id,result=result,expected_hash=e.sha256,computed_hash=computed,timestamp=stamp,detail=detail_text));append(db,eid,e.case_id,"INTEGRITY_VERIFICATION_"+result,u.id,detail_text);db.commit()
 return {"evidence_id":eid,"algorithm":"SHA-256","result":result,"expected_hash":e.sha256,"computed_hash":computed,"timestamp":stamp,"actor_id":u.id,"detail":detail_text,"limitation":"Hash match does not prove truthfulness or authenticity at collection."}
@app.get("/api/evidence/{eid}/history")
def history(eid:str,u:User=Depends(current_user),db:Session=Depends(get_db)):
 e=db.query(Evidence).filter_by(evidence_id=eid).first()
 if not e or not allowed(e,u):raise HTTPException(404,"Evidence not found")
 return [{"event_id":x.event_id,"evidence_id":x.evidence_id,"action":x.action,"actor_id":x.actor_id,"timestamp":x.timestamp,"previous_hash":x.previous_hash,"event_hash":x.event_hash,"reason":x.reason} for x in db.query(CustodyEvent).filter_by(evidence_id=eid).order_by(CustodyEvent.id.asc()).all()]
@app.get("/api/ledger")
def ledger(u:User=Depends(require("Administrator","Auditor","Investigator")),db:Session=Depends(get_db)):
 return [{"event_id":x.event_id,"evidence_id":x.evidence_id,"case_id":x.case_id,"action":x.action,"actor_id":x.actor_id,"timestamp":x.timestamp,"previous_hash":x.previous_hash,"event_hash":x.event_hash,"reason":x.reason} for x in db.query(CustodyEvent).order_by(CustodyEvent.id.desc()).limit(500).all()]
@app.get("/api/ledger/validate")
def ledger_validate(u:User=Depends(require("Administrator","Auditor")),db:Session=Depends(get_db)):return validate(db)
@app.get("/api/reports/audit.csv")
def report(u:User=Depends(require("Administrator","Auditor","Investigator")),db:Session=Depends(get_db)):
 s=io.StringIO();w=csv.writer(s);w.writerow(["event_id","evidence_id","case_id","action","actor_id","timestamp","previous_hash","event_hash","reason"])
 for e in db.query(CustodyEvent).order_by(CustodyEvent.id.asc()).all():
  vals=[e.event_id,e.evidence_id,e.case_id,e.action,str(e.actor_id),e.timestamp,e.previous_hash,e.event_hash,e.reason]
  w.writerow(["'"+v if isinstance(v,str) and v.startswith(("=","+","-","@","\t","\r")) else v for v in vals])
 return Response(s.getvalue(),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=evidencechain-audit-demo.csv"})
LESSONS=[{"key":"sha256","title":"SHA-256 fingerprints","body":"A cryptographic digest fingerprints bytes. If bytes change, the digest will almost certainly change. A match does not prove who created the file or whether its contents are truthful."},{"key":"custody","title":"Chain of custody","body":"Document who collected, held, transferred, accessed, or verified evidence, when and why. Clear hand-offs improve accountability."},{"key":"hashchain","title":"Hash-chained audit logs","body":"Each event includes the prior event hash. Altered payloads or broken links can be detected. A single database owner may still undermine all copies."},{"key":"secure-storage","title":"Secure file storage","body":"Store files outside the public web root, use generated storage names, cap uploads, restrict downloads, and back up securely."},{"key":"limitations","title":"Integrity versus authenticity","body":"MATCH means the bytes equal the recorded fingerprint. It cannot establish whether evidence was staged, genuine, or legally admissible."}]
@app.get("/api/mentor/lessons")
def lessons(u:User=Depends(current_user),db:Session=Depends(get_db)):
 done={x.lesson_key for x in db.query(MentorProgress).filter_by(user_id=u.id,completed=True).all()}
 return [{**l,"completed":l["key"] in done} for l in LESSONS]
@app.post("/api/mentor/progress")
def progress(p:Progress,u:User=Depends(current_user),db:Session=Depends(get_db)):
 if p.lesson_key not in {x["key"] for x in LESSONS}:raise HTTPException(404,"Lesson not found")
 row=db.query(MentorProgress).filter_by(user_id=u.id,lesson_key=p.lesson_key).first()
 if row:row.completed=p.completed
 else:db.add(MentorProgress(user_id=u.id,lesson_key=p.lesson_key,completed=p.completed))
 db.commit();return {"ok":True}
@app.get("/api/admin/users")
def users(u:User=Depends(require("Administrator")),db:Session=Depends(get_db)):
 return [{"id":x.id,"name":x.name,"email":x.email,"role":x.role} for x in db.query(User).all()]
