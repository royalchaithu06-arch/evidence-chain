from datetime import datetime,timezone
from sqlalchemy import String,Integer,Boolean,DateTime,Text,ForeignKey
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base
def now(): return datetime.now(timezone.utc)
class User(Base):
 __tablename__="users"
 id:Mapped[int]=mapped_column(Integer,primary_key=True)
 name:Mapped[str]=mapped_column(String(120))
 email:Mapped[str]=mapped_column(String(255),unique=True,index=True)
 password_hash:Mapped[str]=mapped_column(String(255))
 role:Mapped[str]=mapped_column(String(40),default="Evidence Collector")
class SessionToken(Base):
 __tablename__="sessions"
 id:Mapped[int]=mapped_column(Integer,primary_key=True)
 token_hash:Mapped[str]=mapped_column(String(64),unique=True,index=True)
 user_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
 expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
 revoked:Mapped[bool]=mapped_column(Boolean,default=False)
class Evidence(Base):
 __tablename__="evidence"
 id:Mapped[int]=mapped_column(Integer,primary_key=True)
 evidence_id:Mapped[str]=mapped_column(String(40),unique=True,index=True)
 case_id:Mapped[str]=mapped_column(String(80),index=True)
 evidence_type:Mapped[str]=mapped_column(String(40))
 filename:Mapped[str]=mapped_column(String(255))
 description:Mapped[str]=mapped_column(Text,default="")
 classification:Mapped[str]=mapped_column(String(40),default="Internal")
 collected_at:Mapped[str]=mapped_column(String(40))
 collector_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
 sha256:Mapped[str]=mapped_column(String(64))
 file_size:Mapped[int]=mapped_column(Integer)
 content_type:Mapped[str]=mapped_column(String(120))
 storage_name:Mapped[str]=mapped_column(String(80),unique=True)
 current_custodian_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
class CustodyEvent(Base):
 __tablename__="custody_events"
 id:Mapped[int]=mapped_column(Integer,primary_key=True)
 event_id:Mapped[str]=mapped_column(String(40),unique=True)
 evidence_id:Mapped[str]=mapped_column(String(40),index=True)
 case_id:Mapped[str]=mapped_column(String(80),index=True)
 action:Mapped[str]=mapped_column(String(80))
 actor_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
 recipient_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
 reason:Mapped[str]=mapped_column(Text,default="")
 timestamp:Mapped[str]=mapped_column(String(40))
 previous_hash:Mapped[str]=mapped_column(String(64))
 payload_json:Mapped[str]=mapped_column(Text)
 event_hash:Mapped[str]=mapped_column(String(64),index=True)
class VerificationRun(Base):
 __tablename__="verification_runs"
 id:Mapped[int]=mapped_column(Integer,primary_key=True)
 evidence_id:Mapped[str]=mapped_column(String(40),index=True)
 actor_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
 result:Mapped[str]=mapped_column(String(20))
 expected_hash:Mapped[str]=mapped_column(String(64))
 computed_hash:Mapped[str]=mapped_column(String(64),default="")
 timestamp:Mapped[str]=mapped_column(String(40))
 detail:Mapped[str]=mapped_column(Text,default="")
class MentorProgress(Base):
 __tablename__="mentor_progress"
 id:Mapped[int]=mapped_column(Integer,primary_key=True)
 user_id:Mapped[int]=mapped_column(ForeignKey("users.id"))
 lesson_key:Mapped[str]=mapped_column(String(80))
 completed:Mapped[bool]=mapped_column(Boolean,default=False)
