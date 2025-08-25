from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory, abort, Response, render_template, request, redirect, url_for, flash

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import json
from pathlib import Path
import csv
from io import StringIO 
app = Flask(__name__, template_folder="templates", static_folder="static")

# ----------------------
# Configuration
# ----------------------
# Base directory
BASE_DIR = Path(__file__).parent

# Ensure instance folder exists
instance_path = BASE_DIR / 'instance'
os.makedirs(instance_path, exist_ok=True)

# Database configuration
db_path = instance_path / 'app.db'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production!

# Map configuration
app.config['MAPBOX_ACCESS_TOKEN'] = 'your-mapbox-token'  # Replace with your Mapbox token
app.config['DEFAULT_MAP_CENTER'] = [0, 0]  # Default map center coordinates
app.config['DEFAULT_MAP_ZOOM'] = 2  # Default map zoom level

# Upload configuration
app.config['UPLOAD_FOLDER'] = instance_path / 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "admin_login_page"

# ----------------------
# Database Models
# ----------------------
class AdminUser(UserMixin, db.Model):
    __tablename__ = "admin_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    reporter_name = db.Column(db.String(100))
    country_code = db.Column(db.String(2))
    reporter_phone = db.Column(db.String(20))
    emergency_type = db.Column(db.String(50))
    severity = db.Column(db.Integer, default=5)
    neighborhood = db.Column(db.String(100))
    address = db.Column(db.String(200))
    description = db.Column(db.Text)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    status = db.Column(db.String(20), default="reported")
    resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    attachments = db.relationship("Attachment", backref="incident", cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            "id": self.id,
            "reporter_name": self.reporter_name,
            "country_code": self.country_code,
            "reporter_phone": self.reporter_phone,
            "emergency_type": self.emergency_type,
            "severity": self.severity,
            "neighborhood": self.neighborhood,
            "address": self.address,
            "description": self.description,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "status": self.status,
            "resolved": self.resolved,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "attachments": [a.to_dict() for a in self.attachments],
            "marker_color": self.get_marker_color()
        }
    
    def get_marker_color(self):
        """Return different marker colors based on severity"""
        if self.severity >= 8:
            return "#ff0000"  # Red for high severity
        elif self.severity >= 5:
            return "#ffa500"  # Orange for medium severity
        else:
            return "#ffff00"  # Yellow for low severity

class Attachment(db.Model):
    __tablename__ = "attachments"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"))
    filename = db.Column(db.String(255))
    mimetype = db.Column(db.String(100))
    url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "mimetype": self.mimetype,
            "url": self.url,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    message = db.Column(db.Text)
    category = db.Column(db.String(50))
    area = db.Column(db.String(100))
    geojson = db.Column(db.Text)  # Stored as JSON string
    active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey("admin_users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship("AdminUser")
    
    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "category": self.category,
            "area": self.area,
            "geojson": json.loads(self.geojson) if self.geojson else None,
            "active": self.active,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "creator": self.creator.username if self.creator else None
        }

# ----------------------
# Login Manager
# ----------------------
@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

# ----------------------
# Initial Setup
# ----------------------
def initialize_database():
    """Initialize the database and create tables"""
    try:
        with app.app_context():
            db.create_all()
            if AdminUser.query.count() == 0:
                admin = AdminUser(username="abc")
                admin.set_password("abc@123")  # change in production
                db.session.add(admin)
                db.session.commit()
                print("Created default admin user: abc /abc@123")
    except Exception as e:
        print(f"Failed to initialize database: {str(e)}")
        raise

# CLI command for initialization
@app.cli.command("init-db")
def init_db_command():
    """Initialize the database."""
    initialize_database()
    print("Database initialized.")

# ----------------------
# Routes
# ----------------------
@app.route('/')
def home_redirect():
    return redirect(url_for('home_page'))

@app.route('/home')
def home_page():
    # Pass map configuration to template
    return render_template('home.html', 
                         mapbox_token=app.config['MAPBOX_ACCESS_TOKEN'],
                         default_center=app.config['DEFAULT_MAP_CENTER'],
                         default_zoom=app.config['DEFAULT_MAP_ZOOM'])

@app.route('/user/dashboard')
def user_dashboard_page():
    return render_template('user_dashboard.html',
                         mapbox_token=app.config['MAPBOX_ACCESS_TOKEN'],
                         default_center=app.config['DEFAULT_MAP_CENTER'],
                         default_zoom=app.config['DEFAULT_MAP_ZOOM'])

@app.route('/admin/dashboard')
@login_required
def admin_dashboard_page():
    # Get stats for dashboard
    total_incidents = Incident.query.count()
    resolved_incidents = Incident.query.filter_by(resolved=True).count()
    recent_incidents = Incident.query.order_by(Incident.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         total_incidents=total_incidents,
                         resolved_incidents=resolved_incidents,
                         recent_incidents=recent_incidents,
                         mapbox_token=app.config['MAPBOX_ACCESS_TOKEN'])

@app.route('/admin/incidents')
@login_required
def all_incident_page():
    return render_template('All-incident.html',
                         mapbox_token=app.config['MAPBOX_ACCESS_TOKEN'])

@app.route('/admin/notify')
@login_required
def admin_notify_page():
    return render_template('admin_notify.html',
                         mapbox_token=app.config['MAPBOX_ACCESS_TOKEN'])

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = AdminUser.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'redirect': url_for('admin_dashboard_page')})
            return redirect(url_for('admin_dashboard_page'))
        
        error = "Invalid credentials"
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error}), 401
        return render_template('admin_login.html', error=error)
    
    return render_template('admin_login.html')

@app.route('/admin/reports')
@login_required
def reports_page():
    return render_template('reports.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# ----------------------
# Map and Marker API Endpoints
# ----------------------
@app.get("/api/map/incidents")
def get_incidents_for_map():
    """Get incidents with coordinates for map display"""
    incidents = Incident.query.filter(
        Incident.latitude.isnot(None),
        Incident.longitude.isnot(None)
    ).all()
    
    features = []
    for incident in incidents:
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [incident.longitude, incident.latitude]
            },
            "properties": incident.to_dict()
        })
    
    return jsonify({
        "type": "FeatureCollection",
        "features": features
    })

@app.get("/api/map/alerts")
def get_alerts_for_map():
    """Get active alerts with geojson data for map display"""
    alerts = Alert.query.filter_by(active=True).all()
    
    features = []
    for alert in alerts:
        if alert.geojson:
            try:
                geojson_data = json.loads(alert.geojson)
                if isinstance(geojson_data, dict):
                    geojson_data.update({
                        "properties": {
                            "id": alert.id,
                            "title": alert.title,
                            "category": alert.category
                        }
                    })
                    features.append(geojson_data)
            except json.JSONDecodeError:
                continue
    
    return jsonify({
        "type": "FeatureCollection",
        "features": features
    })

# ----------------------
# Reporting API Endpoints
# ----------------------
@app.get("/api/reports/incidents/csv")
@login_required
def generate_incident_csv():
    """Generate CSV report of incidents"""
    # Get filter parameters
    status = request.args.get("status")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    
    query = Incident.query
    
    if status:
        query = query.filter_by(status=status)
    
    if start_date:
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(Incident.created_at >= start_date)
        except ValueError:
            pass
    
    if end_date:
        try:
            end_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(Incident.created_at <= end_date)
        except ValueError:
            pass
    
    incidents = query.order_by(Incident.created_at.desc()).all()
    
    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "Reporter Name", "Phone", "Emergency Type", "Severity",
        "Neighborhood", "Address", "Status", "Resolved", "Created At"
    ])
    
    # Write data
    for incident in incidents:
        writer.writerow([
            incident.id,
            incident.reporter_name,
            incident.reporter_phone,
            incident.emergency_type,
            incident.severity,
            incident.neighborhood,
            incident.address,
            incident.status,
            "Yes" if incident.resolved else "No",
            incident.created_at.strftime("%Y-%m-%d %H:%M:%S") if incident.created_at else ""
        ])
    
    # Prepare response
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=incidents_report.csv"}
    )

@app.get("/api/reports/incidents/summary")
@login_required
def get_incident_summary():
    """Get summary statistics for incidents"""
    # Count by status
    status_counts = db.session.query(
        Incident.status,
        db.func.count(Incident.id)
    ).group_by(Incident.status).all()
    
    # Count by emergency type
    type_counts = db.session.query(
        Incident.emergency_type,
        db.func.count(Incident.id)
    ).group_by(Incident.emergency_type).all()
    
    # Count by severity
    severity_counts = db.session.query(
        Incident.severity,
        db.func.count(Incident.id)
    ).group_by(Incident.severity).order_by(Incident.severity).all()
    
    # Recent activity
    recent_activity = db.session.query(
        db.func.date(Incident.created_at).label("date"),
        db.func.count(Incident.id).label("count")
    ).group_by(db.func.date(Incident.created_at))
    
    # Apply date filters if provided
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    
    if start_date:
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%d")
            recent_activity = recent_activity.filter(Incident.created_at >= start_date)
        except ValueError:
            pass
    
    if end_date:
        try:
            end_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            recent_activity = recent_activity.filter(Incident.created_at <= end_date)
        except ValueError:
            pass
    
    recent_activity = recent_activity.order_by(db.func.date(Incident.created_at).desc()).limit(30).all()
    
    return jsonify({
        "status_counts": dict(status_counts),
        "type_counts": dict(type_counts),
        "severity_counts": dict(severity_counts),
        "recent_activity": [{"date": str(act.date), "count": act.count} for act in recent_activity]
    })

# ----------------------
# CLI helper to create admin quickly
# ----------------------
@app.cli.command("create-admin")
def create_admin():
    """flask create-admin"""
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    if AdminUser.query.filter_by(username=username).first():
        print("User exists.")
        return
    u = AdminUser(username=username)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    print("Admin created.")

# ----------------------
# Application Startup
# ----------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
