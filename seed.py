from app.database import Base,engine,SessionLocal
from app.models import User
from app.security import pwd
Base.metadata.create_all(bind=engine);db=SessionLocal()
try:
 if not db.query(User).filter_by(email="admin@evidencechain.local").first():
  db.add(User(name="Demo Administrator",email="admin@evidencechain.local",password_hash=pwd.hash("ChangeMe123!"),role="Administrator"));db.commit()
 print("Seed complete; demo administrator available locally.")
finally:db.close()
