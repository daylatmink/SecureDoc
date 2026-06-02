from sqlalchemy import Column, DateTime, String, Text

from .database import Base


class CertificateRecord(Base):
    __tablename__ = "certificates"

    serial_number = Column(String, primary_key=True, index=True)
    owner_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    public_key_pem = Column(Text, nullable=False)
    issuer = Column(String, nullable=False)
    issued_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, nullable=False, default="valid")

