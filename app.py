import pymysql, os
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreateUserForm, LogInForm, AddBugForm
from flask_gravatar import Gravatar
from functools import wraps
from dotenv import load_dotenv

## Load environment variables
load_dotenv()
DB_USERNAME = os.getenv('DB_USERNAME')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST')
DB_DATABASE = os.getenv('DB_DATABASE')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')

## Objects
app = Flask(__name__)
app.config['SECRET_KEY'] = APP_SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap(app)

Base = declarative_base()

app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_DATABASE}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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

#db.create_all()

## FLASK LOGIN
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

## DECORATOR FOR ADMIN ONLY PAGES
def logged_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated:
            pass
        else:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper_function


@app.route("/dashboard")
@logged_only
def dashboard():
    project = Project.query.get(current_user.project_id)
    return render_template("dashboard.html", user=current_user, project=project, page_name="Dashboard")

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
    if bug.project_id != current_user.project_id:
        abort(403)
    project_members = User.query.filter_by(project_id=current_user.project_id).all()    
    return render_template("bug-view.html", bug=bug, members=project_members, page_name=bug.title)

@app.route("/bug/<int:bug_id>/<status>")
@logged_only
def bug_status(bug_id, status):
    bug = Bug.query.get(bug_id)
    if bug.project_id != current_user.project_id:
        abort(403)
    else:
        bug.status = str(status)
        db.session.commit()
    return redirect(url_for('bugs'))

@app.route("/edit-bug/<int:bug_id>", methods=["POST", "GET"])
@logged_only
def bug_edit(bug_id):
    bug = Bug.query.get(bug_id)
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

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)