from flask import Flask, render_template, request, redirect, url_for, flash  # Add flash
from models.database import db, Scan, Vulnerability, User
from scanner.scanner import WebVulnerabilityScanner
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
app.secret_key = 'supersecretkey'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    scans = Scan.query.all()
    return render_template('index.html', scans=scans)

@app.route('/scan', methods=['POST'])
@login_required  # Protect the scan route
def start_scan():
    target_url = request.form.get('url')
    
    # Perform scan
    scanner = WebVulnerabilityScanner(target_url)
    vulnerabilities = scanner.scan()
    
    # Store results
    scan = Scan(target_url=target_url)
    db.session.add(scan)
    
    for vuln in vulnerabilities:
        vulnerability = Vulnerability(
            scan=scan,
            vulnerability_type=vuln['type'],
            url=vuln['url'],
            payload=vuln['payload']
        )
        db.session.add(vulnerability)
    
    db.session.commit()
    return redirect(url_for('results', scan_id=scan.id))

@app.route('/results/<int:scan_id>')
def results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template('results.html', scan=scan)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)