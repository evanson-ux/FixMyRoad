from app import db
from datetime import datetime

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255))
    location = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='Received')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Reporter (citizen who submitted the issue)
    reporter = db.relationship("User", backref="submitted_reports", foreign_keys=[user_id])

    # Assigned officer
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    officer = db.relationship("User", backref="handled_reports", foreign_keys=[assigned_to])

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "description": self.description,
            "image_url": self.image_url,
            "location": self.location,
            "category": self.category,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "assigned_to": self.assigned_to,
            "reporter_name": self.reporter.name if self.reporter else None,
            "officer_name": self.officer.name if self.officer else None
        }
