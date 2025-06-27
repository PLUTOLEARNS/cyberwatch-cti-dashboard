"""
Threat intel data models for storing CTI information
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from models.database import Base

class ThreatIndicator(Base):
    """Model for threat indicators (IOCs)"""
    __tablename__ = 'threat_indicators'
    
    id = Column(Integer, primary_key=True)
    indicator_value = Column(String(255), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)  # IP, Domain, Hash, URL
    threat_score = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    source = Column(String(100))
    
    # Relationship with ThreatReport
    reports = relationship("ThreatReport", back_populates="indicator")
    
    def __repr__(self):
        return f'<ThreatIndicator {self.indicator_value}>'


class ThreatReport(Base):
    """Model for detailed threat reports"""
    __tablename__ = 'threat_reports'
    
    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey('threat_indicators.id'))
    report_date = Column(DateTime, default=datetime.utcnow)
    malware_families = Column(Text)
    confidence_level = Column(Integer)
    
    # Relationship with ThreatIndicator
    indicator = relationship("ThreatIndicator", back_populates="reports")
    
    def __repr__(self):
        return f'<ThreatReport {self.id} for indicator {self.indicator_id}>'
