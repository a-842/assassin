from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from random import shuffle

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ainsworth is good'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    kills = db.Column(db.Integer, default=0)
    deaths = db.Column(db.Integer, default=0)
    score = db.Column(db.Integer, default=0)

    targets = db.relationship('Target', back_populates='hunter', foreign_keys='Target.hunter_id')
    hunters = db.relationship('Target', back_populates='target', foreign_keys='Target.target_id')

class Target(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hunter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    hunter = db.relationship('User', back_populates='targets', foreign_keys=[hunter_id])
    target = db.relationship('User', back_populates='hunters', foreign_keys=[target_id])

    __table_args__ = (db.UniqueConstraint('hunter_id', 'target_id'),)
    
###############
## Make this accessable for my web proxy, you can remove or replace these values
#def custom_url_for(endpoint, **values):
#    url = url_for(endpoint, **values)
#    return url.replace("http://acoult.art:4999", "http://acoult.art/assassin")
#
#app.jinja_env.globals['url_for'] = custom_url_for
#############

@app.route('/ads.txt')
def ads():
    return render_template('ads.txt')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    user_target = None
    if not current_user.is_admin:
        target = Target.query.filter_by(hunter_id=current_user.id).first()
        if target:
            user_target = target.target.username  # Get the target's username
    players = User.query.filter(User.id != current_user.id).filter_by(is_admin=False).all()
    return render_template('dashboard.html', username=current_user.username, target=user_target, players=players)


# Route for users to change their own password
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        if check_password_hash(current_user.password_hash, old_password):
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect old password!', 'danger')

    return render_template('change_password.html')


# Admin panel
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return "Access Denied", 403

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'warning')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'User {username} created successfully!', 'success')

    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin'))


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403

    user = User.query.get(user_id)
    new_password = request.form['new_password']

    if user:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash(f'Password for {user.username} has been reset.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)

            # Redirect admins to the admin panel
            if user.is_admin:
                return redirect(url_for('admin'))

            # Regular users go to the dashboard
            return redirect(url_for('dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Admin panel to start the game
@app.route('/admin/make_game', methods=['POST'])
@login_required
def make_game():
    if not current_user.is_admin:
        return "Access Denied", 403

    # Get all non-admin users
    players = User.query.filter_by(is_admin=False).all()
    shuffle(players)

    for player in players:
        player.kills = 0
        player.deaths = 0
        player.score = 0

    # Assign targets in a circular manner (ring)
    for i in range(len(players)):
        hunter = players[i]
        target = players[(i + 1) % len(players)]  # Wrap around to create a ring
        # Check if target already exists
        existing_target = Target.query.filter_by(hunter_id=hunter.id).first()
        if existing_target:
            db.session.delete(existing_target)  # Remove existing target assignment if any
        # Create a new Target record
        new_target = Target(hunter_id=hunter.id, target_id=target.id)
        db.session.add(new_target)
    
    db.session.commit()
    flash('Game started and targets assigned!', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/end_game', methods=['POST'])
@login_required
def end_game():
    if not current_user.is_admin:
        return "Access Denied", 403

    # Clear all targets
    Target.query.delete()
    db.session.commit()

    flash("Game has been ended. All targets cleared.", "warning")
    return redirect(url_for('admin'))

@app.route('/report_death', methods=['POST'])
@login_required
def report_death():
    killer_id = request.form.get('killer_id')
    victim = current_user  # The logged-in user is reporting their own death

    # Ensure the killer is a valid player
    killer = User.query.get(killer_id)
    if not killer:
        flash("Invalid killer selection.", "danger")
        return redirect(url_for('dashboard'))

    # Check if the victim was part of the game
    target_entry = Target.query.filter_by(hunter_id=victim.id).first()
    if not target_entry:
        flash("You are not in an active game!", "warning")
        return redirect(url_for('dashboard'))

    # Transfer the victim's target to the killer
    victim_target = target_entry.target_id
    if victim_target:
        new_target = Target(hunter_id=killer.id, target_id=victim_target)
        db.session.add(new_target)

    # Update scores and remove the victim
    killer.kills += 1
    killer.score += 1
    victim.deaths += 1
    victim.score -= 1

    # Remove the victim from the game
    Target.query.filter_by(hunter_id=victim.id).delete()
    Target.query.filter_by(target_id=victim.id).delete()

    db.session.commit()
    flash("Your death has been reported!", "success")
    return redirect(url_for('dashboard'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    players = User.query.order_by(User.score.desc()).filter_by(is_admin=False).all()  # Sort by score (highest first)
    return render_template('leaderboard.html', players=players)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:  # First user becomes admin
            admin_user = User(username="admin", password_hash=generate_password_hash("adminpass"), is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin account created (username: admin, password: adminpass)")

    app.run(debug=True, host="0.0.0.0", port="5001")
