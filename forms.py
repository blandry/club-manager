from flask.ext.wtf import Form, TextField, PasswordField, FileField, validators

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
    thumbnail = FileField('Thumbnail', [validators.Required()])

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
