from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, SelectField
from wtforms.validators import DataRequired
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

class AddMemberForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    role = StringField("Role", validators=[DataRequired()])
    submit = SubmitField("Submit")

class EditMemberForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    role = StringField("Role", validators=[DataRequired()])
    submit = SubmitField("Submit1")

class EditProjectForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    submit1 = SubmitField("Submit")

class EditProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    new_password = StringField("New Password")
    submit2 = SubmitField("Submit2")

class SendReportForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    body = CKEditorField("Description", validators=[DataRequired()])
    submit = SubmitField("Report")

class RemindPasstForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    submit = SubmitField("Send")