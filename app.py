import pymysql, os
from flask import Flask, render_template, redirect, url_for, flash, abort
#from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import delete
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreateUserForm, LogInForm, AddBugForm, AddMemberForm, EditMemberForm, EditProjectForm, EditProfileForm
from flask_gravatar import Gravatar
from flask_mail import Mail, Message
from password_generator import PasswordGenerator
from functools import wraps
from dotenv import load_dotenv

## Load environment variables
load_dotenv()
DB_USERNAME = os.getenv('DB_USERNAME')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST')
DB_DATABASE = os.getenv('DB_DATABASE')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

## App set up
app = Flask(__name__)

app.config['SECRET_KEY'] = APP_SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_DATABASE}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

ckeditor = CKEditor(app)
#Bootstrap(app)
mail = Mail(app)
db = SQLAlchemy(app)
Base = declarative_base()

## CONFIGURE TABLES

class Project(db.Model, Base):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), nullable=False)
    members = relationship("User", back_populates="project")
    bugs = relationship("Bug", back_populates="project")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(15), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"))
    project = relationship("Project", back_populates="members")
    bugs = relationship("Bug", back_populates="responsible")

class Bug(db.Model, Base):
    __tablename__ = "bugs"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(60), nullable=False)
    body = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(12), nullable=False)
    status = db.Column(db.String(12), nullable=False)
    responsible_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    responsible = relationship("User", back_populates="bugs")
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"))
    project = relationship("Project", back_populates="bugs")

## Uncomment this for the initial creation of the database
#db.create_all()

## FLASK LOGIN
login_manager = LoginManager()
login_manager.init_app(app)

##FLASK GRAVATAR
gravatar = Gravatar(app,
                    size=250,
                    rating='g',
                    default='identicon',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

## Setup a user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

## Decorator access for login required pages
def logged_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated:
            pass
        else:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper_function

## Decorator access for creators only
def creator_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.role != 'Creator':
            abort(403)
        else:
            pass
        return function(*args, **kwargs)
    return wrapper_function

## Checking user for the access to the requested bug or member
def check_bug_or_member(user, bug=None, member=None):
    if bug:
        if bug.project_id != user.project_id:
            abort(403)
    if member:
        if member.project_id != user.project_id:
            abort(403)


## ROUTES
@app.route("/dashboard")
@logged_only
def dashboard():
    project = Project.query.get(current_user.project_id)
    bugs_inwork = Bug.query.filter_by(project_id=current_user.project_id).filter(Bug.status=='In Work')
    all_bugs = Bug.query.filter_by(project_id=current_user.project_id).limit(5).all()
    project_members = User.query.filter_by(project_id=current_user.project_id).limit(5).all()
    return render_template("dashboard.html", user=current_user, project=project, bugs_inwork=bugs_inwork, members=project_members, all_bugs=all_bugs, page_name="Dashboard")

@app.route("/login", methods=["POST", "GET"])
def login():
    form = LogInForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        requested_user = User.query.filter_by(email=email).first()
        if requested_user:
            if check_password_hash(requested_user.password, password):
                login_user(requested_user)
                return redirect(url_for("dashboard"))
            else:
                flash("Password isn't correct.")
                return redirect(url_for('login'))
        else:
            flash("Such user doesn't exist")
            return redirect(url_for('login'))
    return render_template("auth-login.html", form=form, logged_in=current_user.is_authenticated, page_name="Log In")

@app.route("/register", methods=["POST", "GET"])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Such user exists. You're redirected to the login page")
            return redirect(url_for("login"))
        else:
            hashed_salted_password = generate_password_hash(
                password = form.password.data,
                method = 'pbkdf2:sha256',
                salt_length = 8
            )
            new_project = Project(
                name = form.project_name.data
            )
            new_user = User(
                name = form.name.data,
                password = hashed_salted_password,
                email = form.email.data,
                role = "Creator",
                project = new_project
            )
            
            db.session.add(new_project, new_user)
            db.session.commit()

            # SEND EMAIL TO NEW USER
            msg = Message('Bugfire Sign Up', sender=('Bugfire', 'mail@bugfire.ru'), recipients=[f"{new_user.email}"])
            msg.html = f"<h3>Hi, {new_user.name}</h3><p>You have successfully registered your account and the project. Here are your credentials:</p><p>Email: {new_user.email}</p><p>Password: {form.password.data}</p>"
            mail.send(msg)

            login_user(new_user)
            return redirect(url_for("dashboard"))

    return render_template("auth-register.html", form=form, logged_in=current_user.is_authenticated, page_name="Sign Up")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/forgot-pass")
def forgot_pass():
    return render_template("auth-forgot-password.html")

## BUGS
@app.route("/bugs")
@logged_only
def bugs():
    bugs_list = Bug.query.filter_by(project_id=current_user.project_id).filter((Bug.status=='In Work') | (Bug.status=='Done'))
    project_members = User.query.filter_by(project_id=current_user.project_id).all()
    return render_template("bugs-active.html", bugs=bugs_list, members=project_members, page_name="Active Bugs")

@app.route("/bugs-history")
@logged_only
def bugs_history():
    bugs_list = Bug.query.filter_by(project_id=current_user.project_id).filter((Bug.status=='Cancelled') | (Bug.status=='Deleted'))
    project_members = User.query.filter_by(project_id=current_user.project_id).all()
    return render_template("bugs-history.html", bugs=bugs_list, members=project_members, page_name="Bugs History")

@app.route("/your-bugs")
@logged_only
def your_bugs():
    bugs_list = Bug.query.filter_by(project_id=current_user.project_id).filter((Bug.status=='In Work') | (Bug.status=='Done') & (Bug.responsible_id==current_user.id))
    project_members = User.query.filter_by(project_id=current_user.project_id).all()
    return render_template("bugs-active.html", bugs=bugs_list, members=project_members, page_name="Your Bugs")

@app.route("/add-bug", methods=["POST", "GET"])
@logged_only
def add_bug():
    form = AddBugForm()
    project_members = User.query.filter_by(project_id=current_user.project_id).all()
    form.responsible.choices = [(g.id, g.name) for g in project_members]
    if form.validate_on_submit():
        new_bug = Bug(
            title=form.title.data,
            priority=form.priority.data,
            body=form.body.data,
            responsible_id=form.responsible.data,
            project_id=current_user.project_id,
            status='In Work'
        )
        db.session.add(new_bug)
        db.session.commit()
        return redirect(url_for("bugs"))
    return render_template("add-bug.html", form=form, page_name="Add a Bug")

@app.route("/bug/<int:bug_id>", methods=["POST", "GET"])
@logged_only
def bug(bug_id):
    bug = Bug.query.get(bug_id)
    check_bug_or_member(current_user, bug=bug)

    project_members = User.query.filter_by(project_id=current_user.project_id).all()    
    return render_template("bug-view.html", bug=bug, members=project_members, page_name=bug.title)

@app.route("/bug/<int:bug_id>/<status>")
@logged_only
def bug_status(bug_id, status):
    bug = Bug.query.get(bug_id)
    check_bug_or_member(current_user, bug=bug)

    bug.status = str(status)
    db.session.commit()
    return redirect(url_for('bugs'))

@app.route("/bugs/delete")
@logged_only
@creator_only
def delete_all_bugs():
    statement = delete(Bug).where(Bug.project_id==current_user.project_id)
    db.session.exec(statement)
    return redirect(url_for('bugs'))

@app.route("/edit-bug/<int:bug_id>", methods=["POST", "GET"])
@logged_only
def bug_edit(bug_id):
    bug = Bug.query.get(bug_id)
    check_bug_or_member(current_user, bug=bug)

    edit_form = AddBugForm(
        title=bug.title,
        responsible=bug.responsible_id,
        priority=bug.priority,
        body=bug.body
    )
    project_members = User.query.filter_by(project_id=current_user.project_id).all()
    edit_form.responsible.choices = [(g.id, g.name) for g in project_members]
    if edit_form.validate_on_submit():
        bug.title=edit_form.title.data,
        bug.priority=edit_form.priority.data,
        bug.body=edit_form.body.data,
        bug.responsible_id=edit_form.responsible.data,
        db.session.commit()
        return redirect(url_for("bugs"))

    return render_template("add-bug.html", form=edit_form, page_name=f"Edit {bug.title}")

## MEMBERS
@app.route("/team")
@logged_only
def team():
    project_members = User.query.filter_by(project_id=current_user.project_id).all()
    return render_template("project-members.html", members=project_members, page_name="Project Team")

@app.route("/add-member", methods=["POST", "GET"])
@logged_only
def add_member():
    form = AddMemberForm(password=PasswordGenerator().generate())
    project = Project.query.get(current_user.project_id)
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("User with such email already exists")
            return redirect(url_for("add_member"))
        else:
            hashed_salted_password = generate_password_hash(
                password = form.password.data,
                method = 'pbkdf2:sha256',
                salt_length = 8
            )
            new_user = User(
                name = form.name.data,
                password = hashed_salted_password,
                email = form.email.data,
                role = form.role.data,
                project = project
            )
            db.session.add(new_user)
            db.session.commit()

            # SEND EMAIL TO NEW MEMBER
            msg = Message('Bugfire New Member', sender=('Bugfire', 'mail@bugfire.ru'), recipients=[f"{new_user.email}"])
            msg.html = f"<h3>Hi, {new_user.name}</h3><p>You have been added to the project <b>{project.name}</b>. Here is your account:</p><p>Email: {new_user.email}</p><p>Password: {form.password.data}</p><p>You can log in here: <a href='https://bugfire.ru/login'>bugfire.ru/login</a></p>"
            mail.send(msg)

            return redirect(url_for("team"))
    return render_template("add-member.html", form=form, page_name="Add a Member")

@app.route("/edit-member/<int:member_id>", methods=["POST", "GET"])
@logged_only
def edit_member(member_id):
    member = User.query.get(member_id)
    check_bug_or_member(current_user, member=member)

    edit_form = EditMemberForm(
        name=member.name,
        role=member.role
    )
    if edit_form.validate_on_submit():
        member.name=edit_form.name.data
        member.role=edit_form.role.data
        db.session.commit()
        return redirect(url_for("team"))
    return render_template("add-member.html", form=edit_form, page_name=f"Edit {member.name}")


## SETTINGS
@app.route("/settings", methods=["POST", "GET"])
@logged_only
def settings():
    project = Project.query.get(current_user.project_id)
    user = User.query.get(current_user.id)

    project_form = EditProjectForm(
        title=project.name
    )
    profile_form = EditProfileForm(
        name=current_user.name,
        new_password=""
    )

    if project_form.submit1.data and project_form.validate() and current_user.role == 'Creator':
        project.name=project_form.title.data,
        db.session.commit()
        return redirect(url_for("settings"))
    
    elif profile_form.submit2.data and profile_form.validate():
        user.name=profile_form.name.data
        if profile_form.new_password.data != "":
            hashed_salted_password = generate_password_hash(
                password = profile_form.new_password.data,
                method = 'pbkdf2:sha256',
                salt_length = 8
            )
            user.password=hashed_salted_password
        db.session.commit()
        return redirect(url_for("settings"))

    return render_template("settings.html", project_form=project_form, profile_form=profile_form, user=current_user, page_name="Settings")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)