from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, PrivateMessage, GroupChat, GroupMessage, GroupMember, Notification
from forms import SignUpForm, LoginForm, MessageForm, GroupChatForm, ProfileForm
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from wtforms.validators import DataRequired, Email, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat_dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('chat_dashboard'))
    
    form = SignUpForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already registered')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, 
                       email=form.email.data, 
                       password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chat_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('chat_dashboard'))
        flash('Invalid email or password')
    return render_template('login.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, is_admin=True).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials')
    return render_template('admin_login.html', form=form)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('chat_dashboard'))
    users = User.query.all()
    groups = GroupChat.query.all()
    return render_template('admin_dashboard.html', users=users, groups=groups)

@app.route('/chat/dashboard')
@login_required
def chat_dashboard():
    users = User.query.filter(User.id != current_user.id).all()
    groups = GroupChat.query.join(GroupMember).filter(GroupMember.user_id == current_user.id).all()
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    return render_template('chat_dashboard.html', users=users, groups=groups, notifications=notifications)

@app.route('/chat/private/<int:user_id>', methods=['GET', 'POST'])
@login_required
def private_chat(user_id):
    other_user = User.query.get_or_404(user_id)
    form = MessageForm()
    
    if form.validate_on_submit():
        message = PrivateMessage(
            sender_id=current_user.id,
            receiver_id=user_id,
            content=form.content.data
        )
        db.session.add(message)
        
        # Create notification for receiver
        notification = Notification(
            user_id=user_id,
            content=f"Ujumbe mpya kutoka kwa {current_user.username}: {form.content.data[:30]}...",
            type='chat'
        )
        db.session.add(notification)
        db.session.commit()
        return redirect(url_for('private_chat', user_id=user_id))
    
    # Mark messages as read
    unread_messages = PrivateMessage.query.filter_by(
        sender_id=user_id,
        receiver_id=current_user.id,
        is_read=False
    ).all()
    
    for message in unread_messages:
        message.is_read = True
    db.session.commit()
    
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == user_id)) |
        ((PrivateMessage.sender_id == user_id) & (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp).all()
    
    # Get unread notifications count
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    
    return render_template('private_chat.html', 
                         form=form, 
                         messages=messages, 
                         other_user=other_user,
                         notifications=notifications)

@app.route('/chat/group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_chat(group_id):
    group = GroupChat.query.get_or_404(group_id)
    form = MessageForm()
    
    if form.validate_on_submit():
        message = GroupMessage(
            group_id=group_id,
            sender_id=current_user.id,
            content=form.content.data
        )
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('group_chat', group_id=group_id))
    
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp).all()
    return render_template('group_chat.html', form=form, messages=messages, group=group)

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    # Mark notifications as read
    for notification in notifications:
        notification.is_read = True
    db.session.commit()
    return render_template('notifications.html', notifications=notifications)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    
    if form.validate_on_submit():
        # Check if username is taken by another user
        if form.username.data != current_user.username:
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                flash('Username already taken')
                return redirect(url_for('profile'))
        
        # Check if email is taken by another user
        if form.email.data != current_user.email:
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                flash('Email already registered')
                return redirect(url_for('profile'))
        
        # Handle password change
        if form.current_password.data:
            if not check_password_hash(current_user.password, form.current_password.data):
                flash('Current password is incorrect')
                return redirect(url_for('profile'))
            if form.new_password.data:
                current_user.password = generate_password_hash(form.new_password.data)
        
        # Handle avatar upload
        if form.avatar.data:
            file = form.avatar.data
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Create unique filename
                filename = f"{current_user.id}_{filename}"
                # Create upload folder if it doesn't exist
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                current_user.avatar_url = f"uploads/{filename}"
        
        # Update user details
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.bio = form.bio.data
        
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))
    
    # Pre-fill form with current user data
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.bio.data = current_user.bio
    
    return render_template('profile.html', form=form, user=current_user)

@app.template_filter('get_username')
def get_username(user_id):
    user = User.query.get(user_id)
    return user.username if user else "Unknown User"

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notifications = Notification.query.filter_by(
            user_id=current_user.id, 
            is_read=False
        ).all()
        return {'notifications': notifications}
    return {'notifications': []}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
