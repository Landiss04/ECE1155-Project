from flask import Flask, redirect, render_template, request, url_for, session
from attacks import attack1, attack2, attack3, attack4, attack5
from attacks import login1, login2, login3, login4, login5
from attacks import ATTACK_LOG, INFO_LOG, real_time_attack
from setup_db import access_info_db

app = Flask(__name__)
app.config['SECRET_KEY'] = 'securedatabase'

# Maps attack level to the correct login function
ATTACK_LOGIN_FUNCTIONS = {
    1: login1,
    2: login2,
    3: login3,
    4: login4,
    5: login5,
}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Get attack level from query param, default to 1
    # e.g. /login?level=2 will use login2
    level = int(request.args.get('level', 1))
    session['level'] = level

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        login_fn = ATTACK_LOGIN_FUNCTIONS.get(level, login1)
        success = login_fn(username, password)

        if success:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template(
                'login.html',
                error='Invalid Credentials',
                level=level,
                attack_log=ATTACK_LOG  # show blocked attempts in UI
            )

    return render_template('login.html', level=level)

@app.route('/dashboard')
def dashboard():
    # Redirect to login if no session
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    level = session.get('level', 1)

    # Use the correct info DB depending on attack level
    if level >= 4:
        account = access_info_db(username)
    else:
        account = access_info_db(username)

    return render_template(
        'dashboard.html',
        account=account,
        username=username,
        level=level,
        info_log=INFO_LOG,
        attack_log=ATTACK_LOG
    )

@app.route('/simulate', methods=['GET', 'POST'])
def simulate():
    """
    Route for running the real-time attack simulation.
    Allows configuring number of attacks and delay from the UI.
    """
    results = None

    if request.method == 'POST':
        num_attacks = int(request.form.get('num_attacks', 20))
        delay = float(request.form.get('delay', 0.5))
        results = real_time_attack(num_attacks=num_attacks, delay=delay)

    return render_template(
        'simulate.html',
        results=results,
        attack_log=ATTACK_LOG
    )

@app.route('/logs')
def logs():
    """
    Displays the attack log and info log for inspection.
    Useful for demonstrating what was blocked vs what succeeded.
    """
    return render_template(
        'logs.html',
        attack_log=ATTACK_LOG,
        info_log=INFO_LOG
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)