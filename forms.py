from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, SelectField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

## WTForm

class CreateUserForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    project_name = StringField("Project Name", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

class LogInForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

class AddBugForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    priority = SelectField("Priority", choices=[('Critical', 'Critical'), ('Medium', 'Medium'), ('Soft', 'Soft')], validators=[DataRequired()])
    responsible = SelectField(u'Group', coerce=int, validators=[DataRequired()])
    body = CKEditorField("Body", validators=[DataRequired()])
    submit = SubmitField("Add")