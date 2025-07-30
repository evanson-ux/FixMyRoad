from app import db
from datetime import datetime

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255))
    location = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='Received')  # Default status
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
