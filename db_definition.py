import datetime

from flask import Flask
from flask_sqlalchemy import sqlalchemy, SQLAlchemy

from werkzeug.security import generate_password_hash

db_name = "iskam.db"

app = Flask('iskam')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{db}'.format(db=db_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def _get_date():
	return datetime.datetime.now()

class User(db.Model):

	__tablename__ = 'user'

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(100), unique=True, nullable=False)
	pass_hash = db.Column(db.String(100), nullable=False)
	admin = db.Column(db.Boolean, unique=False, default=False)
	joined = db.Column(db.Date, default=_get_date) 
	approved = db.Column(db.Boolean, default=False)	
	
	def __repr__(self):
		return ''.format(self.username)

class Entries(db.Model):
	
	__tablename__ = 'entries'

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
	user = db.relationship('User', backref=db.backref('user', lazy=True))
	entry = db.Column(db.String(280), nullable=False)
	posted = db.Column(db.Boolean, default=False)
	approved = db.Column(db.Boolean, default=False)
	added = db.Column(db.Date, default=_get_date)

def create_db():
	db.create_all()

def add_admin_user():
	salted_pwd = generate_password_hash('admin', 'sha256')
	admin = User(username='admin', pass_hash=salted_pwd, admin=True, approved=True)
	db.session.add(admin)
	db.session.commit()

if __name__ == '__main__':
	create_db()
	add_admin_user()
