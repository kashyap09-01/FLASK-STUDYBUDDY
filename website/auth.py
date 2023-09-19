from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged In Successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password!', category='error')
        else:
            flash('Email does not exist! Please Sign Up!', category='error')

    return render_template('StudyBuddy.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up',  methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('useremail')
        name = request.form.get('username')
        pass1 = request.form.get('userpassword1')
        pass2 = request.form.get('userpassword2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email Already Exists! Please Login!', category='success')
        if len(name) < 2:
            flash('Signup Unsuccesful. Name must be atleast 2 Characters.', category='error')
        if pass1 != pass2:
            flash('Signup Unsuccesful. Passwords do not match.', category='error')
        if len(pass1) < 7:
            flash('Signup Unsuccesful. Password must be atleast 7 characters.', category='error')
        else:
            new_user = User(email=email, username=name, password = generate_password_hash(pass1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Signup Successful. Account Created!', category='success')
            login_user(new_user, remember=True)
            return redirect(url_for('views.home'))
        return render_template('StudyBuddy.html')
