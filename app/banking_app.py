from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy 
from queries import login_attack1, login_attack2, login_attack3, login_attack4

#initializing the application
app = Flask(__name__)


@app.route('/')
def login():
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
