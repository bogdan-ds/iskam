import datetime

from sqlalchemy.orm import sessionmaker
from flask import Flask, render_template, request, url_for, redirect, flash, session, abort
from db_definition import User, Entries
from flask_sqlalchemy import sqlalchemy, SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import generate_password_hash, check_password_hash

### Config ###
db_name = "iskam.db"

app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address
)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{db}'.format(db=db_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'XXX'

db = SQLAlchemy(app)

##############

def get_obj_session_and_commit(db_obj):
	obj_session = db.session.object_session(db_obj)
	try:
		obj_session.commit()
	except:
		obj_session.rollback()
	return obj_session

@app.route('/user/<username>/entries/add/', methods=['GET', 'POST'])
def add_entries(username):
	if not session.get(username):
		abort(403)
	user = User.query.filter_by(username=username).one()
	if request.method == 'POST':
		if not request.form['entry']:
			flash('Entry cannot be empty')
		elif len(request.form['entry']) > 280:
			flash('Entry cannot exceed 280 characters. Current length is {}'.format(len(request.form['entry'])))
		else:
			new_entry = Entries(user=user, entry=request.form['entry'])
			current_db_sessions = db.session.object_session(new_entry)
			current_db_sessions.add(new_entry)
			try:
				current_db_sessions.commit()
			except:
				current_db_sessions.rollback()
			flash('Entry successfully added')
	return render_template('add_entries.html', username=username)		

@app.route('/user/<username>/entries/list/', methods=['GET', 'POST'])
def list_entries(username):
	if not session.get(username):
		abort(403)
	user = User.query.filter_by(username=username).one()
	if request.method == 'GET':
		if user.admin:
			entries = Entries.query.all()
		else:
			entries = Entries.query.filter(Entries.user.has(username=username))
		if not entries:
			flash('No entries to show')
	if request.method == 'POST':
		selected_entries = request.form.getlist('entries')
		deleted_entries = request.form.getlist('delete_entries')
		if selected_entries and user.admin:
			entries = []
			for entry in selected_entries:
				e = Entries.query.filter_by(id=entry).first()
				e.approved = True
				get_obj_session_and_commit(e)
				entries.append(e)
			flash('Entries have been approved')
		elif deleted_entries:
			entries = []
			for entry in deleted_entries:
				e = Entries.query.get(entry)
				if e.user.username == user.username or user.admin:
					obj_sess = db.session.object_session(e)
					obj_sess.delete(e)
					obj_sess.commit()
					entries.append(e)
					flash('Entries have been deleted')
				else:
					flash('No permissions to delete')
			
	return render_template('list_entries.html', entries=entries, user=user)
		

@app.route("/user/<username>/", methods=['GET'])
def home(username):
	if not session.get(username):
		return redirect(url_for('login'))
	user = User.query.filter_by(username=username).one()
	
	return render_template('home.html', username=username, user=user)	
	
@app.route('/users/', methods=['GET', 'POST'])
def users():
	if not session['username']:
                return redirect(url_for('login'))
	user = User.query.filter_by(username=session['username']).one()
	if not user.admin:
		return redirect(url_for('home', username=session.get(username)))
	if request.method == 'POST':
		usernames = request.form.getlist('username')
		del_user = request.form.getlist('delete_users')
		if usernames:
			for user in usernames:
				new_user = User.query.filter_by(username=user).one()
				new_user.approved = True
				get_obj_session_and_commit(new_user)
			flash('New users have been approved')
		elif del_user:
			for user in del_user:
				u = User.query.filter_by(username=user).one()
				obj_sess = db.session.object_session(u)
				obj_sess.delete(u)
				obj_sess.commit()
			flash('Users have been deleted')
	all_users = User.query.filter_by(admin=False).all()
	return render_template('users.html', users=all_users)
	
@app.route('/', methods=['GET'])
@app.route("/login/", methods=["GET", "POST"])
@limiter.limit("15 per day")
def login():
	if session.get('username'):
		return redirect(url_for('home', username=session['username']))
	if request.method == 'POST':
		username = request.form['username']
                password = request.form['password']
		if not (username and password):
			flash('Username and password cannot be empty')
			return redirect(url_for('login'))
		else:
			username = username.strip()
			password = password.strip()
		user = User.query.filter_by(username=username).one()
		if user and check_password_hash(user.pass_hash, password):
			session[username] = True
			session['username'] = username
			return redirect(url_for("home", username=username))
		else:
			flash("Invalid username or password.")
	return render_template('login.html')
			
@app.route('/signup/', methods=['GET', 'POST'])
@limiter.limit("10 per day")
def signup():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		confirmed_pass = request.form['confirm_pass']

		if not (username and password):
			flash('Username or Password cannot be empty')
			return redirect(url_for('signup'))
		elif password != confirmed_pass:
			flash('Passwords do not match')
			return redirect(url_for('signup'))
		else:
			username = username.strip()
			password = password.strip()
		hashed_pwd = generate_password_hash(password, 'sha256')
		new_user = User(username=username, pass_hash=hashed_pwd)
		db.session.add(new_user)
		try:
			db.session.commit()
		except sqlalchemy.exc.IntegrityError:
			flash("Username {u} is not available.".format(u=username))
			db.session.rollback()
			return redirect(url_for('signup'))
		finally:
			db.session.close()

		flash('User account has been created.')
		session[username] = True
                session['username'] = username
		return redirect(url_for('home', username=username))

	return render_template('signup.html')

@app.route("/logout/<username>/", methods=['GET'])
def logout(username):
	session.pop('username', None)	
	session.pop(username, None)
	flash('Logged out.')
	return redirect(url_for('login'))

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5001, debug=True)
