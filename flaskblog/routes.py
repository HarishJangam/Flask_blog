from flaskblog import app, db, bcrypt
from flask import render_template, url_for, flash, redirect
from flaskblog.forms import RegisterForm, LoginForm
from flask_login import login_user, current_user, logout_user, login_required
from flaskblog.models import User


@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash("Login Unsuccessful. Please check email or password", "danger")

    return render_template("login.html", tittle="login", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RegisterForm()
    if form.validate_on_submit():
        hash_pas = bcrypt.generate_password_hash(form.password.data)
        user = User(
            username=form.username.data, email=form.email.data, password=hash_pas
        )
        db.session.add(user)
        db.session.commit()
        flash(f"Account created for {form.username.data}", "success")
        return redirect(url_for("login"))
    return render_template("register.html", tittle="register", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))
