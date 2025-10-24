import os
import io
import base64
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base
import bcrypt
import pyotp
import qrcode

# ---------- Config ----------
DATABASE_URL = os.environ.get('HASHI_DB') or 'sqlite:///hashi_zone.db'
SECRET_KEY = os.environ.get('HASHI_SECRET_KEY') or 'change_this_secret_in_prod'
ADMIN_USERNAME = os.environ.get('HASHI_ADMIN_USER') or 'hashi'
ADMIN_PASSWORD_HASH = os.environ.get('HASHI_ADMIN_HASH')  # bcrypt hash string
ADMIN_RAW_PASSWORD = os.environ.get('HASHI_ADMIN_PASS')  # raw password for dev
AUTO_LOGIN_DEV = os.environ.get('HASHI_AUTO_LOGIN', 'false').lower() in ('1', 'true', 'yes')

# ---------- App ----------
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# SQLAlchemy setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------- Models ----------
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    pw_hash = Column(String(200), nullable=False)
    totp_secret = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Content(Base):
    __tablename__ = 'content'
    id = Column(Integer, primary_key=True)
    title = Column(String(200))
    body = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class ProxyEntry(Base):
    __tablename__ = 'proxies'
    id = Column(Integer, primary_key=True)
    address = Column(String(200), nullable=False)
    notes = Column(Text)
    added_by = Column(String(150))
    added_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ---------- Utilities ----------
def get_db():
    return SessionLocal()

def hash_password(raw: str) -> str:
    return bcrypt.hashpw(raw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(raw: str, pw_hash: str) -> bool:
    try:
        return bcrypt.checkpw(raw.encode('utf-8'), pw_hash.encode('utf-8'))
    except Exception:
        return False

def ensure_admin_user():
    db = get_db()
    admin = db.query(User).filter_by(username=ADMIN_USERNAME).first()
    if admin:
        db.close()
        return
    if ADMIN_PASSWORD_HASH:
        pw_hash = ADMIN_PASSWORD_HASH
    elif ADMIN_RAW_PASSWORD:
        pw_hash = hash_password(ADMIN_RAW_PASSWORD)
    else:
        db.close()
        raise RuntimeError("No admin password provided. Set HASHI_ADMIN_HASH or HASHI_ADMIN_PASS.")
    admin = User(username=ADMIN_USERNAME, pw_hash=pw_hash)
    db.add(admin)
    db.commit()
    db.close()

# ---------- Flask-Login user ----------
class AdminUser(UserMixin):
    def __init__(self, id_, username):
        self.id = str(id_)
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    u = db.query(User).filter_by(id=int(user_id)).first()
    db.close()
    if not u:
        return None
    return AdminUser(u.id, u.username)

# ---------- Forms ----------
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    totp = StringField('2FA code (if enabled)', validators=[Length(max=10)])
    remember = BooleanField('Remember me')
    submit = SubmitField('Sign in')

class ContentForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Save')

class ProxyForm(FlaskForm):
    address = StringField('Proxy address (host:port)', validators=[DataRequired(), Length(max=200)])
    notes = TextAreaField('Notes', validators=[Length(max=1000)])
    submit = SubmitField('Add Proxy')

# ---------- Routes ----------
@app.before_first_request
def setup():
    try:
        ensure_admin_user()
    except RuntimeError as e:
        app.logger.error(str(e))

@app.route('/')
def index():
    if AUTO_LOGIN_DEV:
        db = get_db()
        u = db.query(User).filter_by(username=ADMIN_USERNAME).first()
        db.close()
        if u:
            login_user(AdminUser(u.id, u.username))
            return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("6 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        totp_code = form.totp.data.strip()
        remember = form.remember.data

        db = get_db()
        user = db.query(User).filter_by(username=username).first()
        db.close()

        if not user or not verify_password(password, user.pw_hash):
            flash("Invalid username or password", "danger")
            return render_template('login.html', form=form)

        if user.totp_secret:
            if not totp_code:
                flash("2FA code required", "warning")
                return render_template('login.html', form=form)
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                flash("Invalid 2FA code", "danger")
                return render_template('login.html', form=form)

        login_user(AdminUser(user.id, user.username), remember=remember)
        flash(f"Welcome back, {user.username}.", "success")
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    items = db.query(Content).order_by(Content.created_at.desc()).all()
    proxies = db.query(ProxyEntry).order_by(ProxyEntry.added_at.desc()).all()
    db.close()
    return render_template('dashboard.html', items=items, proxies=proxies)

# ---------- Add content & proxies routes omitted for brevity (same as your code) ----------

# ---------- Run ----------
if __name__ == '__main__':
    try:
        ensure_admin_user()
    except RuntimeError as e:
        print("Startup error:", e)
        raise

    port = int(os.environ.get("PORT", 5000))  # <-- Dynamic port for Render
    app.run(host='0.0.0.0', port=port, debug=False)
