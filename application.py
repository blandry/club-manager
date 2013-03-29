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
from werkzeug import check_password_hash, generate_password_hash
from datetime import datetime, timedelta, date
from flask import Flask, redirect, url_for, request, render_template, abort, send_from_directory, jsonify
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, make_secure_token
from flask.ext.mail import Mail, Message
from flask.ext.uploads import configure_uploads, UploadSet, IMAGES
from flask.ext.admin import Admin, BaseView, expose
from flask.ext.admin.model import BaseModelView
from flask.ext.admin.contrib.sqlamodel import ModelView
from forms import *

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
receipts = UploadSet('receipts', ['pdf'])
racethumbnails = UploadSet('racethumbnails', IMAGES)
userthumbnails = UploadSet('userthumbnails', IMAGES)
configure_uploads(app, (receipts, racethumbnails, userthumbnails))

class ReimbursementRequestStatus():
    """ Enum of statuses for reimbursement requests """
    PENDING = "Pending"
    PROCESSED ="Processed"
    INVALID = "Invalid"
    DEFAULT = PENDING

admin = Admin(app)

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

    def has_valid_dues_for(self, race_id):
        race = Race.query.get(race_id)
        if not race:
            return False
        for due in self.dues:
            if due.valid_on(race.date):
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

class Dues(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User',  backref=db.backref('dues', lazy='dynamic'))
    amount = db.Column(db.Float)
    number_of_races = db.Column(db.Integer)
    days_valid = db.Column(db.Integer)
    start_date = db.Column(db.Date)

    def __init__(self, user, amount, number_of_races, days_valid, start_date=None):
        self.user = user
        self.amount = amount
        self.number_of_races = number_of_races
        self.days_valid = days_valid
        if not start_date:
            start_date = date.today()
        self.start_date = start_date

    def __repr__(self):
        return "%s %s %s" % (str(self.amount), str(self.start_date), str(self.user))

    @property
    def duration(self):
        return timedelta(days=self.days_valid)

    @property
    def number_of_races_left(self):
        return (self.number_of_races - len(self.dues_utilisations.all()))

    @property
    def end_date(self):
        return self.start_date + self.duration

    def valid_on(self, date):
        return (self.start_date <= date and date <= self.end_date and self.number_of_races_left > 0)

    @property
    def valid_on_today(self):
        today = date.today()
        return self.valid_on(today)

class DuesUtilisation(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    reimbursement_item_id = db.Column(db.Integer, db.ForeignKey('reimbursement_item.id'))
    reimbursement_item = db.relationship('ReimbursementItem',  backref=db.backref('dues_utilisations', lazy='dynamic'))
    dues_id = db.Column(db.Integer, db.ForeignKey('dues.id'))
    dues = db.relationship('Dues',  backref=db.backref('dues_utilisations', lazy='dynamic'))

    def __init__(self, reimbursement_item, dues):
        self.reimbursement_item = reimbursement_item
        self.dues = dues

race_tags = db.Table('race_tags',
                     db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
                     db.Column('race_id', db.Integer, db.ForeignKey('race.id'))
)

class Tag(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return str(self.name)

class Race(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    description = db.Column(db.Text)
    date = db.Column(db.Date)
    thumbnail = db.Column(db.String)
    external_registration_url = db.Column(db.String)
    tags = db.relationship('Tag', secondary=race_tags,
                           backref=db.backref('races', lazy='dynamic'))

    def __init__(self, name, description, date, thumbnail="", external_registration_url="", tags=[]):
        self.name = name
        self.description = description
        self.date = date
        self.thumbail = thumbnail
        self.external_registration_url = external_registration_url
        self.tags = tags

    def __repr__(self):
        return '%s %s' % (str(self.name), str(self.date))

    @property
    def thumbnail_url(self):
        return racethumbnails.url(self.thumbnail)

    @property
    def number_registered(self):
        return len(self.logistics_registrations.all())

    def has_tag(self, tag_name):
        return Tag.query.filter_by(name=tag_name).first() in self.tags

class LogisticsRegistration(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User',  backref=db.backref('logistics_registrations', lazy='dynamic'))
    race_id = db.Column(db.Integer, db.ForeignKey('race.id'))
    race = db.relationship('Race',  backref=db.backref('logistics_registrations', lazy='dynamic'))

    def __init__(self, user, race):
        self.user = user
        self.race = race

    def __repr__(self):
        return "Logistics Registration %s %s" % (str(self.race), str(self.user))

class ReimbursementRequest(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User',  backref=db.backref('reimbursement_requests', lazy='dynamic'))
    race_id = db.Column(db.Integer, db.ForeignKey('race.id'))
    race = db.relationship('Race',  backref=db.backref('reimbursement_requests', lazy='dynamic'))
    status = db.Column(db.String(120))
    comments = db.Column(db.Text)
    
    def __init__(self, user, race, status=ReimbursementRequestStatus.DEFAULT, comments=""):
        self.user = user
        self.race = race
        self.status = status
        self.comments = comments

    def __repr__(self):
        return "Reimbursement %s %s" % (str(self.race), str(self.user))

class ReimbursementItem(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    reimbursement_request_id = db.Column(db.Integer, db.ForeignKey('reimbursement_request.id'))
    reimbursement_request = db.relationship('ReimbursementRequest',  backref=db.backref('reimbursement_items', lazy='dynamic'))
    reason = db.Column(db.String)
    amount = db.Column(db.Float)
    receipt = db.Column(db.String)

    def __init__(self, reimbursement_request, reason, amount, receipt):
        self.reimbursement_request = reimbursement_request
        self.reason = reason
        self.amount = amount
        self.receipt = receipt

    def __repr__(self):
        return "%s %s %s" % (str(self.reimbursement_request), str(self.reason), str(self.amount))

    @property
    def receipt_url(self):
        return receipts.url(self.receipt)

# # # # #

@app.route("/", methods=["GET"])
def home():
    return render_template("home.html", active_page="home")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=unicode(form.email.data)).first():
            thumbnail = userthumbnails.save(form.thumbnail.data)
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

@app.route("/races", methods=["GET"])
@login_required
def races():
    races = Race.query.order_by(Race.date.asc())
    return render_template("races.html", active_page='races', races=races)

@app.route("/logistics", methods=["GET"])
@login_required
def logistics():
    registrations = current_user.logistics_registrations.all()
    return render_template("logistics.html", active_page='logistics', registrations=registrations)

@app.route("/reimbursements", methods=["GET"])
@login_required
def reimbursements():
    requests = current_user.reimbursement_requests.all()
    return render_template("reimbursements.html", active_page='reimbursements', requests=requests)

@app.route("/dues", methods=["GET"])
@login_required
def dues():
    dues = current_user.dues.all()
    return render_template("dues.html", active_page='dues', dues=dues)

# # # # #

class UserAdmin(ModelView):

    can_create = False
    column_list = ('first_name', 'last_name', 'email', 'active')

    def is_accessible(self):
        return current_user.is_authenticated()

    def __init__(self, session, **kwargs):
        super(UserAdmin, self).__init__(User, session, **kwargs)

admin.add_view(UserAdmin(db.session))

# # # # #

if __name__ == "__main__":
    app.run(debug=settings.DEBUG)
