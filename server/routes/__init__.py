from flask import Blueprint, request, jsonify
from models.User import User
from models.Report import Report
from app import db
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from werkzeug.security import check_password_hash


main = Blueprint('main', __name__)

@main.route('/')
def home():
    return {'message': 'FixMyRoad API is working!'}

VALID_ROLES = ['user', 'officer', 'admin']

@main.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if not name or not email or not password or not role:
        return jsonify({'error': 'All fields (name, email, password, role) are required.'}), 400

    if role not in VALID_ROLES:
        return jsonify({'error': f"Invalid role. Allowed roles: {', '.join(VALID_ROLES)}"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered.'}), 400

    hashed_password = generate_password_hash(password)

    user = User(name=name, email=email, role=role)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Signup successful.'}), 201

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'error': 'No account found with this email'}), 404

    if not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Incorrect password'}), 401

    access_token = create_access_token(identity=user.id)

    return jsonify({
        'message': 'Login successful',
        'token': access_token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role
        }
    }), 200

@main.route('/register-officer', methods=['POST'])
@jwt_required()
def register_officer():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'admin':
        return jsonify({'message': 'Only admin can register officers'}), 403

    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Officer already exists'}), 409

    officer = User(name=data['name'], email=data['email'], role='officer')
    officer.set_password(data['password'])

    db.session.add(officer)
    db.session.commit()

    return jsonify({'message': 'Officer registered successfully'}), 201

import re

def is_valid_url(url):
    return re.match(r'^https?:\/\/.*\.(jpg|jpeg|png|gif)$', url, re.IGNORECASE)

@main.route('/create', methods=['POST'])
@jwt_required()
def create_report():
    data = request.get_json()
    user_id = get_jwt_identity()

    required_fields = ['description', 'location', 'category']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field.capitalize()} is required'}), 400

    image_url = data.get('image_url')
    if image_url and not is_valid_url(image_url):
        return jsonify({'error': 'Invalid image URL. Must be a valid image link.'}), 400

    report = Report(
        user_id=user_id,
        description=data['description'],
        location=data['location'],
        category=data['category'],
        image_url=image_url
    )

    db.session.add(report)
    db.session.commit()

    return jsonify({'message': 'Report submitted successfully.'}), 201

@main.route('/reports', methods=['GET'])
@jwt_required()
def get_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    results = [{
        'id': report.id,
        'user_id': report.user_id,
        'description': report.description,
        'image_url': report.image_url,
        'location': report.location,
        'category': report.category,
        'status': report.status,
        'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for report in reports]

    return jsonify(results), 200

@main.route('/report/<int:report_id>/status', methods=['PUT'])
@jwt_required()
def update_report_status(report_id):
    data = request.get_json()
    new_status = data.get('status')

    if new_status not in ['Received', 'In Progress', 'Resolved']:
        return jsonify({'message': 'Invalid status'}), 400

    report = Report.query.get(report_id)
    if not report:
        return jsonify({'message': 'Report not found'}), 404

    report.status = new_status
    db.session.commit()

    return jsonify({'message': 'Status updated successfully'}), 200

@main.route('/report/<int:report_id>', methods=['GET'])
@jwt_required()
def get_report_by_id(report_id):
    report = Report.query.get(report_id)

    if not report:
        return jsonify({'message': 'Report not found'}), 404

    return jsonify({
        'id': report.id,
        'user_id': report.user_id,
        'description': report.description,
        'image_url': report.image_url,
        'location': report.location,
        'category': report.category,
        'status': report.status,
        'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }), 200

@main.route('/report/<int:report_id>', methods=['DELETE'])
@jwt_required()
def delete_report(report_id):
    report = Report.query.get(report_id)
    user_id = get_jwt_identity()

    if not report:
        return jsonify({'message': 'Report not found'}), 404

    if str(report.user_id) != str(user_id):
        return jsonify({'message': 'Unauthorized'}), 403

    db.session.delete(report)
    db.session.commit()

    return jsonify({'message': 'Report deleted successfully'}), 200

@main.route('/report/<int:report_id>', methods=['PUT'])
@jwt_required()
def update_report(report_id):
    report = Report.query.get(report_id)
    user_id = get_jwt_identity()

    if not report:
        return jsonify({'message': 'Report not found'}), 404

    if str(report.user_id) != str(user_id):
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()

    report.description = data.get('description', report.description)
    report.location = data.get('location', report.location)
    report.category = data.get('category', report.category)
    report.image_url = data.get('image_url', report.image_url)

    db.session.commit()

    return jsonify({'message': 'Report updated successfully'}), 200

@main.route('/my-reports', methods=['GET'])
@jwt_required()
def get_my_reports():
    user_id = get_jwt_identity()
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.created_at.desc()).all()

    results = [{
        'id': r.id,
        'description': r.description,
        'location': r.location,
        'category': r.category,
        'image_url': r.image_url,
        'status': r.status,
        'created_at': r.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for r in reports]

    return jsonify(results), 200

@main.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'admin':
        return jsonify({'message': 'Access forbidden'}), 403

    role = request.args.get('role')
    email = request.args.get('email')

    query = User.query
    if role:
        query = query.filter_by(role=role)
    if email:
        query = query.filter(User.email.contains(email))

    users = query.all()
    result = [{
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'role': user.role
    } for user in users]

    return jsonify(result), 200

@main.route('/promote/<int:user_id>', methods=['PUT'])
@jwt_required()
def promote_user(user_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'admin':
        return jsonify({'message': 'Access forbidden'}), 403

    user_to_promote = User.query.get(user_id)
    if not user_to_promote:
        return jsonify({'message': 'User not found'}), 404

    user_to_promote.role = 'admin'
    db.session.commit()

    return jsonify({'message': f'User {user_to_promote.email} promoted to admin'}), 200

@main.route('/officer/report/<int:report_id>/status', methods=['PUT'])
@jwt_required()
def officer_update_report_status(report_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user.role != 'officer':
        return jsonify({'message': 'Access denied'}), 403

    report = Report.query.get(report_id)
    if not report:
        return jsonify({'message': 'Report not found'}), 404

    if report.assigned_to != user.id:
        return jsonify({'message': 'You are not assigned to this report'}), 403

    data = request.get_json()
    new_status = data.get('status')

    if new_status not in ['In Progress', 'Resolved']:
        return jsonify({'message': 'Invalid status update'}), 400

    report.status = new_status
    db.session.commit()

    return jsonify({'message': f'Status updated to {new_status}'}), 200
@main.route('/delete_user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'admin':
        return jsonify({'message': 'Access forbidden'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': f'User {user.name} deleted successfully'}), 200
@main.route('/reports/status/<status>', methods=['GET'])
@jwt_required()
def get_reports_by_status(status):
    reports = Report.query.filter_by(status=status.capitalize()).order_by(Report.created_at.desc()).all()

    results = []
    for report in reports:
        results.append({
            'id': report.id,
            'user_id': report.user_id,
            'description': report.description,
            'image_url': report.image_url,
            'location': report.location,
            'category': report.category,
            'status': report.status,
            'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify(results), 200

@main.route('/admin/reports/assigned', methods=['GET'])
@jwt_required()
def get_admin_assigned_reports():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'admin':
        return jsonify({'message': 'Access forbidden'}), 403

    reports = Report.query.filter_by(assigned_to=user.id).order_by(Report.created_at.desc()).all()

    result = []
    for report in reports:
        result.append({
            'id': report.id,
            'description': report.description,
            'image_url': report.image_url,
            'location': report.location,
            'category': report.category,
            'status': report.status,
            'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'assigned_to': report.assigned_to
        })

    return jsonify(result), 200

# ✅ PUT /admin/reports/<report_id>/assign
@main.route('/admin/reports/<int:report_id>/assign', methods=['PUT'])
@jwt_required()
def assign_report(report_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'admin':
        return jsonify({'message': 'Only admins can assign reports'}), 403

    data = request.get_json()
    officer_id = data.get('officer_id')

    if not officer_id:
        return jsonify({'message': 'officer_id is required'}), 400

    officer = User.query.get(officer_id)
    if not officer or officer.role != 'officer':
        return jsonify({'message': 'Officer not found or invalid role'}), 404

    report = Report.query.get(report_id)
    if not report:
        return jsonify({'message': 'Report not found'}), 404

    report.assigned_to = officer_id  # assumes your Report model has `assigned_to` column
    db.session.commit()

    return jsonify({'message': f'Report {report_id} assigned to Officer {officer.name}'}), 200
@main.route('/officer/reports/assigned', methods=['GET'])
@jwt_required()
def get_officer_assigned_reports():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user.role != 'officer':
        return jsonify({"error": "Unauthorized"}), 403

    reports = Report.query.filter_by(assigned_to=user.id).order_by(Report.created_at.desc()).all()

    return jsonify([{
        "id": r.id,
        "description": r.description,
        "location": r.location,
        "status": r.status,
        "category": r.category,
        "image_url": r.image_url,
        "created_at": r.created_at
    } for r in reports]), 200
@main.route('/reports/<int:report_id>/resolve', methods=['PATCH'])
@jwt_required()
def resolve_report(report_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or user.role != 'officer':
        return jsonify({"error": "Unauthorized"}), 403

    report = Report.query.filter_by(id=report_id, assigned_to=user.id).first()
    if not report:
        return jsonify({"error": "Report not found or not assigned to you"}), 404

    report.status = 'Resolved'
    db.session.commit()

    return jsonify({"message": "Report marked as resolved"}), 200
@main.route('/view-status', methods=['POST'])
def view_status():
    data = request.json
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    reports = Report.query.filter_by(user_id=user_id).all()

    if not reports:
        return jsonify({"message": "No reports found for this user"}), 404

    return jsonify([
        {
            "id": r.id,
            "description": r.description,
            "status": r.status,
            "location": r.location,
            "category": r.category,
            "created_at": r.created_at
        }
        for r in reports
    ]), 200
@main.route('/user/<int:user_id>/reports', methods=['GET'])
def get_user_reports(user_id):
    reports = Report.query.filter_by(user_id=user_id).all()

    if not reports:
        return jsonify({"message": "No reports found for this user"}), 404

    return jsonify([
        {
            "id": r.id,
            "description": r.description,
            "status": r.status,
            "location": r.location,
            "category": r.category,
            "created_at": r.created_at
        }
        for r in reports
    ]), 200

@main.route('/admin/reports', methods=['GET'])
@jwt_required()
def filter_reports():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'admin':
        return jsonify({"msg": "Admins only"}), 403

    status = request.args.get('status')
    category = request.args.get('category')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = Report.query

    if status:
        query = query.filter_by(status=status)
    if category:
        query = query.filter_by(category=category)
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")
            query = query.filter(Report.created_at.between(start, end))
        except:
            return jsonify({"msg": "Invalid date format. Use YYYY-MM-DD"}), 400

    reports = query.all()
    return jsonify([{
        "id": r.id,
        "description": r.description,
        "status": r.status,
        "category": r.category,
        "location": r.location,
        "created_at": r.created_at
    } for r in reports]), 200
@main.route('/admin/reports/filter', methods=['GET'])
@jwt_required()
def filter_reports_by_status_or_user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user or user.role != 'admin':
        return jsonify({'error': 'Only admins can access this'}), 403

    status = request.args.get('status')
    user_id = request.args.get('user_id')

    query = Report.query

    if status:
        query = query.filter_by(status=status)
    
    if user_id:
        query = query.filter_by(user_id=user_id)

    reports = query.order_by(Report.created_at.desc()).all()

    results = []
    for report in reports:
        results.append({
            'id': report.id,
            'user_id': report.user_id,
            'description': report.description,
            'image_url': report.image_url,
            'location': report.location,
            'category': report.category,
            'status': report.status,
            'assigned_to': report.assigned_to,
            'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify(results), 200
