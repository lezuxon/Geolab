import os
import secrets
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, login_manager
from models import User, ForumPost
from forms import TipForm, RegistrationForm, LoginForm

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    if not os.path.exists('instance'):
        os.makedirs('instance')

    db_file = 'instance/site.db'

    if not os.path.exists(db_file):
        print("Creating a new db")
        db.create_all()

        try:
            hashed_password = generate_password_hash('gelabarkalaia', method='pbkdf2:sha256')
            admin = User(
                username='gela',
                email='barkalaia@gela.com',
                password=hashed_password,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user has been created successfully")
        except Exception as e:
            print(f"Error creating an admin user: {str(e)}")
    else:
        db.create_all()


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256'
        )

        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        flash('Your account has been created.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have logged out.')
    return redirect(url_for('home'))


@app.route('/forum', methods=['GET', 'POST'])
def forum():
    form = TipForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = current_user.username if current_user.is_authenticated else "Undefined"
            post = ForumPost(
                name=username,
                message=form.message.data
            )

            db.session.add(post)
            db.session.commit()

            flash('Your post has been added.')
            return redirect(url_for('forum'))
        else:
            flash('Try again later.')

    posts = ForumPost.query.all()
    is_admin = False
    if current_user.is_authenticated:
        is_admin = current_user.is_admin

    return render_template('forum_posts.html', form=form, posts=posts, is_admin=is_admin)


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    if not current_user.is_admin:
        flash("You don't have the admin privelages")
        return redirect(url_for('forum'))

    post = ForumPost.query.get_or_404(post_id)

    db.session.delete(post)
    db.session.commit()

    flash('Post has been deleted.')
    return redirect(url_for('forum'))


if __name__ == '__main__':
    app.run(debug=True)
