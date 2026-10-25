import hashlib,secrets,os
from datetime import datetime,timedelta,timezone
from passlib.context import CryptContext
from fastapi import Depends,HTTPException
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .database import get_db
from .models import User,SessionToken
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto")
bearer=HTTPBearer(auto_error=False)
def h(token): return hashlib.sha256(token.encode()).hexdigest()
def new_session(db,user):
 token=secrets.token_urlsafe(32)
 db.add(SessionToken(token_hash=h(token),user_id=user.id,expires_at=datetime.now(timezone.utc)+timedelta(hours=int(os.getenv("SESSION_TTL_HOURS","12")))))
 db.commit();return token
def current_user(c:HTTPAuthorizationCredentials=Depends(bearer),db:Session=Depends(get_db)):
 if not c: raise HTTPException(401,"Authentication required")
 s=db.query(SessionToken).filter_by(token_hash=h(c.credentials),revoked=False).first()
 if not s or s.expires_at.replace(tzinfo=timezone.utc)<datetime.now(timezone.utc): raise HTTPException(401,"Session expired or invalid")
 u=db.query(User).filter_by(id=s.user_id).first()
 if not u: raise HTTPException(401,"Invalid session")
 return u
def require(*allowed):
 def dep(u:User=Depends(current_user)):
  if u.role not in allowed: raise HTTPException(403,"Insufficient permissions")
  return u
 return dep
