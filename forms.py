from flask.ext.wtf import Form, TextField, PasswordField, FileField, validators, TextAreaField, DateField, SelectMultipleField, BooleanField, file_required, HiddenField
from flask.ext.admin.form import DatePickerWidget
from flask.ext.admin.contrib.sqlamodel.fields import QuerySelectMultipleField, QuerySelectField

class RegistrationForm(Form):
    email = TextField('Email Address', [validators.Required(),
                                        validators.Email(),
                                        validators.Length(max=254)])
    password = PasswordField('Password', [validators.Required(),
                                          validators.EqualTo('confirm', message='Passwords must match.'),
                                          validators.Length(min=6, max=30)])
    confirm = PasswordField('Repeat Password', [validators.Required()])
    first_name = TextField('First Name', [validators.Required()])
    last_name = TextField('Last Name', [validators.Required()])
    thumbnail = FileField('Thumbnail')

class ChangePasswordForm(Form):
    old_password = PasswordField('Old Password', [validators.Required(),
                                                  validators.Length(max=30)])                                          
    new_password = PasswordField('New Password', [validators.Required(),
                                                  validators.EqualTo('new_confirm',message='Passwords must match.'),
                                                  validators.Length(min=6, max=30)])
    new_confirm = PasswordField('Repeat New Password', [validators.Required()])
    
class LoginForm(Form):
    email = TextField('Email Address', [validators.Required(),
                                        validators.Email(),
                                        validators.Length(max=254)])
    password = PasswordField('Password', [validators.Required(),
                                          validators.Length(max=30)])

class ReimbursementRequestForm(Form):
    name = TextField('Name', [validators.Required()])
    race = QuerySelectField('Race', [validators.Optional()], allow_blank=True)
    comments = TextAreaField('Comments')

class ReimbursementItemForm(Form):
    request_id = HiddenField('Reimbursement request id', [validators.Required(), validators.Regexp('^[0-9]\d*$')])
    reason = TextField('Reason', [validators.Required()])
    amount = TextField(label='Amount', validators=[validators.Required(), 
                                                   validators.Regexp('^([0-9]{1,3},([0-9]{3},)*[0-9]{3}|[0-9]+)(.[0-9][0-9])?$', message='Invalid amount.')])
    receipt = FileField('Receipt PDF', [file_required('')])

class AdminRaceForm(Form):
    name = TextField('Name', [validators.Required()])
    description = TextAreaField('Description')
    date = DateField('Date', [validators.Required()], widget=DatePickerWidget())
    thumbnail = FileField('Thumbnail')
    external_registration_url = TextField('Registration URL')
    tags = QuerySelectMultipleField('Tags', description="Hold down ctrl (Windows) or command (Mac) to select multiple options.")

class AdminTagForm(Form):
    name = TextField('Name', [validators.Required()])

class AdminUserForm(Form):
    active = BooleanField("Active")
    user_types = QuerySelectMultipleField('User Types', description="Hold down ctrl (Windows) or command (Mac) to select multiple options.")

class AdminUserTypeForm(Form):
    name = TextField('Name', [validators.Required()])
