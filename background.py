from TwitterAPI import TwitterAPI
from flask import Flask 
from db_definition import Entries
from flask_sqlalchemy import sqlalchemy, SQLAlchemy


### conf ###
consumer_key = 'XXX'
consumer_secret = 'XXX'
access_token_key = 'XXX'
access_token_secret = 'XXX'
max_retries = 3

db_name = "iskam.db"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{db}'.format(db=db_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'XXX'

db = SQLAlchemy(app)
############

def post_tweet(api, entry):	
	r = api.request('statuses/update', {'status': entry})
	return r.status_code

def select_entry():
	entry = Entries.query.filter_by(posted=False).order_by(Entries.added).limit(1).scalar()
	if entry:
		api = TwitterAPI(consumer_key, consumer_secret, access_token_key, access_token_secret)
		while True:
			res_code = post_tweet(api, entry.entry)
			if res_code != 200 and retries != max_retries:
				retries += 1
				continue
			obj_sess = db.session.object_session(entry)
			entry.posted = True
			obj_sess.commit()
			break

if __name__ == '__main__':
	select_entry()

