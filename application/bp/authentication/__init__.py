from flask import Blueprint, render_template, redirect, url_for, flash, request
from application.bp.authentication.forms import RegisterForm, LoginForm
from application.database import User
from flask_login import login_user, login_required, current_user, logout_user

authentication = Blueprint('authentication', __name__, template_folder='templates')

@authentication.route('/registration', methods=['POST', 'GET'])
def registration():
    # Prevent 500 error by providing an empty form to the template
    form = RegisterForm()
    return render_template('registration.html', form=form)

@authentication.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('User Not Found', 'danger')
        elif not user.check_password(form.password.data):
            flash('Password Incorrect', 'danger')
        else:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('authentication.dashboard'))
    return render_template('login.html', form=form)

@authentication.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user_id=current_user.id)

@authentication.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('homepage.homepage'))
