import sqlite3
import hashlib

# Database paths
VULNERABLE_DB = "db/login_vulnerable.db"
SECURE_DB = "db/login_secure.db"
SNH_DB = "db/login_snh.db"
INFO_DB = "db/info.db"

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

# ATTACK 1 — Simple SQL Injection (login_vulnerable.db)
# Uses raw string concatenation, plaintext passwords.
# Should be breakable with a basic OR '1'='1' injection.
# Returns: True if login succeeds, False otherwise

def login_attack1(username: str, password: str) -> bool:
    conn = sqlite3.connect(VULNERABLE_DB)
    cur = conn.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';" 
    cur.execute(query) 
    result = cur.fetchone()
    conn.close()

    return result is not None

# ATTACK 2 — SQL Injection with valid inputs (login_secure.db)
# Still plaintext passwords but uses parameterized queries.
# Should resist basic injections, but if the attacker knows the password, they can still log in.
# Returns: True if login succeeds, False otherwise

def login_attack2(username: str, password: str) -> bool:
    pass

# ATTACK 3 — Second order SQL injection (login_snh.db)
# Parameterized queries + hash & salt. No plaintext password stored.
# Returns: True if login succeeds, False otherwise

def login_attack3(username: str, password: str) -> bool:
    pass

# ATTACK 4 — Second order injection + dynamic access control (login_snh.db)
# Same as attack 3 but system detects breach and rehashes credentials.
# Returns: True if login succeeds, False otherwise

def login_attack4(username: str, password: str) -> bool:
    pass

# INFO DB QUERY — Retrieve account info after successful login
# Used by the app to display the banking dashboard.
# Should only be reachable after a successful login function above.
# Returns: dict with full_name and balance, or None if not found

def get_account_info(username: str):
    conn = sqlite3.connect(INFO_DB)
    cur = conn.cursor()
    cur.execute("SELECT full_name, balance FROM accounts WHERE username = ?", (username,))
    
    result = cur.fetchone()
    conn.close()

    if result is None:
        return None
    
    return {"full_name": result[0], "balance": result[1]}