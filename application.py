import sys
import os
import string
import random
import hashlib
import shutil
import urllib
import hashlib
import json
import settings
from werkzeug import check_password_hash, generate_password_hash, FileStorage
from datetime import datetime, timedelta, date
from flask import Flask, redirect, url_for, request, render_template, abort, send_from_directory, jsonify
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, make_secure_token
from flask.ext.mail import Mail, Message
from flask.ext.uploads import configure_uploads, UploadSet, IMAGES
from flask.ext.admin import Admin, BaseView, expose
from flask.ext.admin.model import BaseModelView
from flask.ext.admin.contrib.sqlamodel import ModelView
from forms import RegistrationForm, ChangePasswordForm, LoginForm, AdminRaceForm, AdminTagForm, AdminUserForm, AdminUserTypeForm, ReimbursementRequestForm, ReimbursementItemForm

# # # # #

app = Flask(__name__)
app.secret_key = settings.SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = settings.DATABASE_DEV if settings.DEBUG else settings.DATABASE_PROD
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.setup_app(app)
login_manager.login_view = "login"
@login_manager.user_loader
def load_user(id):
    return User.query.get(id)

app.config.update(settings.SMTP_SETTINGS)
mail = Mail(app)

app.config['UPLOADS_DEFAULT_DEST'] = 'uploads'
userthumbnails = UploadSet('userthumbnails', IMAGES)
configure_uploads(app, (userthumbnails,))

admin = Admin(app, name="Raspberry Agent Admin")

# # # # #

class UserType(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return str(self.name)

    def is_allowed_to(self, rule_name):
        if not self.rules.filter_by(name=rule_name).first():
            return False
        return True

rules = db.Table('rules',
                 db.Column('user_type_id', db.Integer, db.ForeignKey('user_type.id')),
                 db.Column('rule_id', db.Integer, db.ForeignKey('rule.id'))
)

class Rule(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True)
    user_types = db.relationship('UserType', secondary=rules,
                                 backref=db.backref('rules', lazy='dynamic'))

    def __init__(self, name, user_types=[]):
        self.name = name
        self.user_types = user_types

    def __repr__(self):
        return str(self.name)

users = db.Table('users',
                 db.Column('user_type_id', db.Integer, db.ForeignKey('user_type.id')),
                 db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    active = db.Column(db.Boolean)
    user_types = db.relationship('UserType', secondary=users, backref=db.backref('users', lazy='dynamic'))    
    first_name = db.Column(db.String(120))
    last_name = db.Column(db.String(120))
    thumbnail = db.Column(db.String)

    def __init__(self, email, password, active=False, user_types=[], first_name="", last_name="", thumbnail=""):
        self.email = unicode(email)
        self.password = generate_password_hash(password)
        self.active = active
        self.user_types = user_types
        self.first_name = first_name
        self.last_name = last_name
        self.thumbnail = thumbnail

    def __repr__(self):
        return self.name

    @property
    def name(self):
        return "%s %s" % (str(self.first_name), str(self.last_name))

    @property
    def thumbnail_url(self):
        return userthumbnails.url(self.thumbnail)

    def is_active(self):
        return self.active

    def activate(self, token_value):
        for token in self.activationtokens.all():
            if token.check_if_valid(token_value):
                self.active = True
                db.session.commit()
                break
        return self.active

    def update_password(self, new_password):
        self.password = generate_password_hash(new_password)
        db.session.commit()

    def is_allowed_to(self, rule_name):
        for user_type in self.user_types:
            if user_type.is_allowed_to(rule_name):
                return True
        return False

    @staticmethod
    def generate_password(size=10, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
        return ''.join(random.choice(chars) for x in range(size))

class ActivationToken(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User',  backref=db.backref('activationtokens', lazy='dynamic'))
    duration = db.Column(db.Interval)
    creation_time = db.Column(db.DateTime)
    value = db.Column(db.String(120))

    def __init__(self, user, value=None, seconds_valid=600):
        self.user = user
        self.duration = timedelta(seconds=seconds_valid)
        self.creation_time = datetime.utcnow()
        if not value:
            value = hashlib.sha224(str(random.getrandbits(256))).hexdigest()
        self.value = value

    @property
    def is_expired(self):
        now = datetime.utcnow()
        return ((now-self.creation_time)>self.duration)

    def check_value(self, checked_value):
        return self.value == checked_value

    def check_if_valid(self, checked_value):
        return (not(self.is_expired) and self.check_value(checked_value))

class Device(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('devices', lazy='dynamic'))
    gc_username = db.Column(db.String(120))
    gc_password = db.Column(db.String(120))

    def __init__(self, device_id, user, gc_username, gc_password):
        self.device_id = device_id
        self.user = user
        self.gc_username = gc_username
        self.gc_password = gc_password


# # # # #

@app.route("/", methods=["GET"])
def home():
    return render_template("home.html", active_page="home")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=unicode(form.email.data)).first():
            if form.thumbnail.data:
                thumbnail = userthumbnails.save(form.thumbnail.data)
            else:
                thumbnail = userthumbnails.save(FileStorage(open('static/img/user.svg')))
            user = User(form.email.data, form.password.data, first_name=form.first_name.data, 
                    last_name=form.last_name.data, thumbnail=thumbnail)
            activation_token = ActivationToken(user)
            db.session.add(user)
            db.session.add(activation_token)
            db.session.commit()
            email_activation_link(user.email, user.id, activation_token.value)
            message = "A confirmation email has been sent to <strong>%s</strong>. You have 5 minutes to check your email and activate your account." % user.email
            return render_template("message.html", active_page='none', message=message)
        form.email.errors = ['Email address already registered']
    return render_template("register.html", active_page='none', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=unicode(form.email.data)).first()
        if user and check_password_hash(user.password, form.password.data) and user.active:
            login_user(user)
            return redirect(request.args.get("next") or url_for("home"))
        if user:
            form.password.errors = ['Invalid password.']
            password_link = '%s?id=%s' % (url_for('send_new_password'), user.id)
            return render_template('login.html', active_page='none', form=form, password_link=password_link)
        form.email.errors = ['Invalid email address.']
    return render_template('login.html', active_page='none', form=form)

@app.route("/logout", methods=["GET"])
def logout():
    logout_user()
    return redirect(url_for("home"));

@app.route("/activate", methods=["GET"])
def activate_user():
    id = request.args.get("id")
    token_value = request.args.get("token_value")
    if not id or not token_value:
        message = 'Missing activation information.'
        return render_template("message.html", active_page='none', message=message)
    user = User.query.get(id)
    if not user:
        message = 'Invalid user id.'
        return render_template("message.html", active_page='none', message=message)
    if user.activate(token_value):
        message = 'Success! Your account has been activated. You may now <a href="%s">login</a>.' % url_for('login')
        return render_template("message.html", active_page='none', message=message)
    activationlink = '%s?id=%s' % (url_for('send_activation_link'), user.id)
    message = 'Invalid or expired activation link. <a href="%s">Click here</a> to get a new one.' % activationlink
    return render_template("message.html", active_page='none', message=message)

@app.route("/send-activation-link", methods=["GET"])
def send_activation_link():
    id = request.args.get("id")
    user = User.query.get(id)
    if not user:
        message = 'Invalid user id.'
        return render_template("message.html", active_page='none', message=message)
    activation_token = ActivationToken(user)
    db.session.add(activation_token)
    db.session.commit()
    email_activation_link(user.email, user.id, activation_token.value)
    message = "A confirmation email has been sent to <strong>%s</strong>. You have 5 minutes to check your email and activate your account." % user.email
    return render_template("message.html", active_page='none', message=message)

@app.route("/send-new-password", methods=["GET"])
def send_new_password():
    id = request.args.get("id")
    user = User.query.get(id)
    if not user:
        message = 'Invalid user id.'
        return render_template("message.html", active_page='none', message=message)
    new_password = User.generate_password()
    user.update_password(new_password)
    email_new_password(user.email, new_password)
    message = "A new password has been sent to <strong>%s</strong>." % user.email 
    return render_template("message.html", active_page='none', message=message)

def email_activation_link(email, user_id, token_value):
    activation_link = "%s%s?id=%s&token_value=%s" % (settings.HOST_ADDRESS, url_for("activate_user"), user_id, token_value)
    if settings.DEBUG:
        print "Activation link: %s" % activation_link
    else:
        body = render_template("email/activation.html", activation_link=activation_link)
        msg = Message("Account activation", recipients=[email])
        msg.html = body
        mail.send(msg)

def email_new_password(email, new_password):
    if settings.DEBUG:
        print "New password: %s" % new_password
    else:
        body = render_template("email/new_password.html", new_password=new_password)
        msg = Message("New password request", recipients=[email])
        msg.html = body
        mail.send(msg)

# authorization required

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.old_password.data):
            current_user.update_password(form.new_password.data)
            db.session.commit()
            message = "Your password has been changed."
            return render_template("message.html", active_page='none', message=message)
        else:
            form.old_password.errors = ["Old password incorrect."]
    return render_template('change_password.html', active_page='none', form=form)

@app.route("/unclaimed-devices", methods=["GET"])
@login_required
def unclaimed_devices():
    claimed_devices = [d.device_id for d in Device.query.all()]
    unclaimed_devices = []
    for (dirpath, dirnames, filenames) in os.walk('/home/blandry/.config/garmin-extractor'):
        unclaimed_devices.extend([d for d in dirnames if d.isdigit() and int(d) not in claimed_devices])
        break
    return render_template("unclaimed_devices.html", 
                           unclaimed_devices=unclaimed_devices);

@app.route("/claim-device/<device_id>")
@login_required
def claim_device(device_id):
    return redirect(url_for("home"));

# # # # #

class AdminModelView(ModelView):
    
    def is_accessible(self):
        if current_user.is_authenticated():
            return current_user.is_allowed_to('admin')
        return False

class UserAdmin(AdminModelView):

    can_create = False
    column_list = ('first_name', 'last_name', 'email', 'active')

    def __init__(self, session, **kwargs):
        super(UserAdmin, self).__init__(User, session, **kwargs)

    def edit_form(self, obj=None):
        form = AdminUserForm(active=obj.active, user_types=obj.user_types)
        form.user_types.query_factory=lambda:UserType.query.all()
        return form

    def update_model(self, form, model):
        model.active = form.active.data
        model.user_types = form.user_types.data
        db.session.commit()
        return True

class UserTypeAdmin(AdminModelView):

    column_list = ('name',)

    def __init__(self, session, **kwargs):
        super(UserTypeAdmin, self).__init__(UserType, session, **kwargs)

    def create_form(self, obj=None):
        form = AdminUserTypeForm()
        return form

    def edit_form(self, obj=None):
        form = AdminUserTypeForm(name=obj.name)
        return form

    def create_model(self, form):
        type = UserType(form.name.data)
        db.session.add(type)
        db.session.commit()
        return True

    def update_model(self, form, model):
        model.name = form.name.data
        db.session.commit()
        return True


admin.add_view(UserAdmin(db.session, name='Manage users', category='Users'))
admin.add_view(UserTypeAdmin(db.session, name='Manage user types', category='Users'))

# # # # #

if __name__ == "__main__":
    app.run(debug=settings.DEBUG)
