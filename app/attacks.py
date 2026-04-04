import sqlite3
import hashlib
import time

from app.setup_db import ATTACK_LOG, INFO_LOG, access_info_db_snh, is_valid_password, is_valid_username, access_info_db, update_username
from app.setup_db import LOGIN_DB, LOGIN_SNH, ALLOWED_CHARS_PASSWORD, ALLOWED_CHARS_USERNAME
from app.setup_db import hash_password, unhash_password

# Usernames & passwords for each level of attack
ATTACK_USERNAMES = [
    "OR 1=1",          # Basic injection for Attack 1
    "attacker_user"     
]

ATTACK_PASSWORDS = [
    "OR 1=1",          # Basic injection for Attack 1
    "0OR(1=1)#",       # More sophisticated injection that bypasses simple input checks for Attack 2
    "password123",     # Matching password with jsmith for second order injection in Attack 3
    "",
    "",
]

def login1(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_DB)
    cur = conn.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';" 
    cur.execute(query) 
    result = cur.fetchone()
    conn.close()

    # Permit access to info database and return account balance if login successful, otherwise return False
    if result:
        INFO_LOG.append((username, password))
        return access_info_db(username)
    return False

def login2(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_DB)
    cur = conn.cursor()

    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Skipping invalid user: {username}")
        return False

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';"
    cur.execute(query)
    result = cur.fetchone()
    conn.close()

    # Permit access to info database and return account balance if login successful, otherwise return False
    if result:
        INFO_LOG.append((username, password))
        return access_info_db(username)
    return False

def login3(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_DB)
    cur = conn.cursor()

    # Input validation should still be in place to block obviously malicious inputs, even if parameterized queries are used.
    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Skipping invalid user: {username}")
        return False
    query = "SELECT * FROM users WHERE username = ? AND password = ?;"
    cur.execute(query, (username, password))
    result = cur.fetchone()
    conn.close()

    # Permit access to info database and return account balance if login successful, otherwise return False
    if result:
        INFO_LOG.append((username, password))
        update_username(username, ATTACK_PASSWORDS[2]) # Change everyone with matching password to have the malicious username for second order injection
        return access_info_db(username)
    else:
        ATTACK_LOG.append(f"Failed parameterized login attempt for user: {username}, password: {password}")
    return False

def login4(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_DB)
    cur = conn.cursor()

    # Input validation should still be in place to block obviously malicious inputs, even if parameterized queries are used.
    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Skipping invalid user: {username}")
        return False
    query = "SELECT * FROM users WHERE username = ? AND password = ?;"
    cur.execute(query, (username, password))
    result = cur.fetchone()
    conn.close()

    # Permit access to info database and return account balance if login successful, otherwise return False
    if result:
        INFO_LOG.append((username, password))
        update_username(username, ATTACK_PASSWORDS[2]) # Change everyone with matching password to have the malicious username for second order injection
        return access_info_db(username)
    else:
        ATTACK_LOG.append(f"Failed parameterized login attempt for user: {username}, password: {password}")
    return False

def login5(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_SNH)
    cur = conn.cursor()

    # Input validation should still be in place to block obviously malicious inputs, even if parameterized queries are used.
    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Skipping invalid user: {username}")
        return False
    query = "SELECT * FROM users WHERE username = ? AND password = ?;"
    cur.execute(query, (username, password))
    result = cur.fetchone()
    conn.close()

    # Permit access to info database and return account balance if login successful, otherwise return False
    if result:
        INFO_LOG.append((username, password))
        update_username(username, ATTACK_PASSWORDS[2]) # Change everyone with matching password to have the malicious username for second order injection
        return access_info_db_snh(username, malicious=True)
    else:
        ATTACK_LOG.append(f"Failed parameterized login attempt for user: {username}, password: {password}")
    return False

# ATTACK 1 — Simple SQL Injection (login_vulnerable.db) ' OR '1'='1 -> bypasses login
# Uses raw string concatenation, plaintext passwords.
# Should be breakable with a basic OR '1'='1' injection.
def attack1() -> bool:
    return login1(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0])

# ATTACK 2 — SQL Injection with valid inputs (login_input_check.db)
# Will contain 2 attacks:
# 1) Basic injection should be blocked by input validation.
# 2) More sophisticated injection using parentheses/comments that bypasses simple input checks : 0OR(1=1)#
def attack2() -> bool:
    return login2(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0]) or login2(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[1])

# ATTACK 3 — Second order SQL injection (login_parameterized.db)
# Will contain 3 attacks:
# 1) Basic injection should be blocked by input validation.
# 2) More sophisticated injection using parentheses/comments that bypasses simple input checks : 0OR(1=1)#
# 3) Second order injection. Insert normal username and password into database,
# but take advantage of common passwords to change username to a malicious payload that allows login bypass
def attack3() -> bool:
    return login3(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0]) or login3(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[2])

# ATTACK 4 — All attacks but on salt and hash database
def attack4() -> bool:
    return login4(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0]) or login4(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[2])


# ATTACK 5 - Extra Credit
# Key is known to attacker, dynamic access control should detect breach and rehash all credentials with new salt, preventing second order injection attack. 
# This simulates a breach detection system that could be implemented in a real application to prevent further damage after detecting an attack.
def attack5() -> bool:
    # First perform the attack that should succeed with the known key
    return login4(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0]) or login4(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[2])

