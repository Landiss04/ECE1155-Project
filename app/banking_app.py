from flask import Flask, redirect, render_template, request, url_for, session
from queries import login_attack1, get_account_info

app = Flask(__name__)
app.config['SECRET_KEY'] = 'securedatabase' #in a real application, we would need this to be more secure, but for our purposes, this is sufficient.s

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success = login_attack1(username, password)
        if success:
            session['username'] = username
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid Credentials')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    username = session.get('username')
    account = get_account_info(username) # passing in the username to keep track of the login session and retrieve the correct account info
    return render_template('dashboard.html', account=account)

if __name__ == '__main__':
    app.run(debug=True)