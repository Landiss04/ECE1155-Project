import hashlib
import os
import re
import sqlite3
from time import time

# Database paths
LOGIN_DB = "db/login.db"
LOGIN_SNH = "db/login_snh.db"
INFO_DB = "db/info.db"
INFO_DB_SNH = "db/info_snh.db"

# --- Helpers ---
def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

def access_info_db(username: str) -> dict:
    conn = sqlite3.connect(INFO_DB)
    cur = conn.cursor()
    cur.execute("SELECT balance FROM accounts WHERE username = ?", (username,))
    balance_result = cur.fetchone()
    conn.close()
    if balance_result:
        print(f"[+] Login successful for {username}. Account balance: ${balance_result[0]:.2f}")
    else:
        print(f"[+] Login successful for {username}. No account info found.")

def access_info_db_snh(username: str, malicious: bool) -> dict:
    conn = sqlite3.connect(INFO_DB_SNH)
    if malicious:
        start_time = time.time()
        # Simulate breach detection and dynamic access control by rehashing all credentials with a new salt
        new_salt = "newsalt123" # In a real system, this would be randomly generated and stored securely
        conn1 = sqlite3.connect(LOGIN_SNH)
        cur1 = conn1.cursor()
        cur = conn.cursor()
        cur.execute("SELECT username, password FROM users")
        users = cur.fetchall()
        for username, password, name, balance in users:
            new_hashed_password = hash_password(password, new_salt)
            cur1.execute("UPDATE users SET password = ? WHERE username = ?", (new_hashed_password, username))
        conn.commit()
        conn.close()
        end_time = time.time()
        global TIME_DOWN
        TIME_DOWN += end_time - start_time
    cur = conn.cursor()
    cur.execute("SELECT balance FROM accounts WHERE username = ?", (username,))
    balance_result = cur.fetchone()
    conn.close()
    if balance_result:
        print(f"[+] Login successful for {username}. Account balance: ${balance_result[0]:.2f}")
    else:
        print(f"[+] Login successful for {username}. No account info found.")

def update_username(new_username: str, password: str = None) -> int:
    conn = sqlite3.connect(LOGIN_DB)
    cur = conn.cursor()
    cur.execute("UPDATE users SET username = ? WHERE password = ?", (new_username, password))
    conn.commit()
    conn.close()

def is_valid_username(username: str) -> bool:
    """Check if username contains only allowed characters."""
    return all(c in ALLOWED_CHARS_USERNAME for c in username)

def is_valid_password(password: str) -> bool:
    """Check if password contains only allowed characters."""
    return all(c in ALLOWED_CHARS_PASSWORD for c in password)

def gen_salt():
    """Generate a random 16-byte hex salt."""
    return os.urandom(16).hex()

def hash_password(password: str, salt: str) -> str:
    """SHA-256 hash a password with the given salt."""
    return hashlib.sha256((salt + password).encode()).hexdigest()

# --- Fake users: (username, password, full_name, balance) ---

USERS = [
    ("jsmith",    "password123",  "John Smith",       12500.75),
    ("ajohnson",  "securepass!",  "Alice Johnson",    98200.00),
    ("bwilliams", "qwerty456",    "Bob Williams",      3340.50),
    ("mgarcia",   "hunter2",      "Maria Garcia",     54780.20),
    ("tdavis",    "letmein99",    "Tom Davis",         1200.00),
    ("swilson",   "pass@word1",   "Sarah Wilson",     23100.60),
    ("rmoore",    "abc123xyz",    "Robert Moore",      8750.30),
    ("ltaylor",   "p@ssw0rd",     "Laura Taylor",     67000.00),
    ("kanderson", "monkey99",     "Kevin Anderson",   15500.90),
    ("nthomas",   "sunshine7",    "Nancy Thomas",      4400.10),
]

# Attack database. Everytime a attack is attempted and prevented, store the attack string in this list. This simulates an attack log that could be used for dynamic access control (e.g. rehashing credentials after a detected breach).
ATTACK_LOG = []

# Log all usernames and passwords that were eventually granted acces to info database
INFO_LOG = []

TIME_DOWN = 0 # Total time the system is down due to detected breaches (for dynamic access control simulation)

# Acceptable characters for usernames and passwords (for input validation in Attack 2)
# Usernames: letters + digits only. Passwords: letters, digits, and common symbols, no spaces.
ALLOWED_CHARS_USERNAME = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
ALLOWED_CHARS_PASSWORD = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=,./?'\"")


#note that claude was used to generate this code, as we deemed generating the databases 
#not to be in the scope of this project, and we wanted to focus on the attacks/countermeasures of the databases instead

# ---------------------------------------------------------------
# Login database
# ---------------------------------------------------------------

def setup_login():
    conn = sqlite3.connect("db/login_vulnerable.db")
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)

    for username, password, _, _ in USERS:
        # Intentionally storing plaintext password — this is the vulnerable db
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )

    conn.commit()
    conn.close()
    print("[+] login_vulnerable.db created (Attack 1 — plaintext, no parameterization).")


# Salt and hash all passwords
def setup_login_snh():
    conn = sqlite3.connect("db/login_snh.db")
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            salt     TEXT NOT NULL,
            hash     TEXT NOT NULL
        )
    """)

    for username, password, _, _ in USERS:
        salt = gen_salt()
        hashed = hash_password(password, salt)
        cur.execute(
            "INSERT INTO users (username, salt, hash) VALUES (?, ?, ?)",
            (username, salt, hashed)
        )

    conn.commit()
    conn.close()
    print("[+] login_snh.db created (Attacks 3 & 4 — salt + hash, no plaintext password).")

# ---------------------------------------------------------------
# INFO DATABASE — info.db (shared across all attacks)
# This is the target — the data the attacker is trying to reach.
# ---------------------------------------------------------------

def setup_info_db():
    conn = sqlite3.connect("db/info.db")
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("""
        CREATE TABLE accounts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            balance   REAL NOT NULL
        )
    """)

    for username, _, full_name, balance in USERS:
        cur.execute(
            "INSERT INTO accounts (username, full_name, balance) VALUES (?, ?, ?)",
            (username, full_name, balance)
        )

    conn.commit()
    conn.close()
    print("[+] info.db created (shared target database).")

def setup_info_db_snh():
    conn = sqlite3.connect("db/info_snh.db")
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("""
        CREATE TABLE accounts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            plaintext_password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            balance   REAL NOT NULL
        )
    """)

    for username, plaintext_password, full_name, balance in USERS:
        cur.execute(
            "INSERT INTO accounts (username, plaintext_password, full_name, balance) VALUES (?, ?, ?, ?)",
            (username, plaintext_password, full_name, balance)
        )

    conn.commit()
    conn.close()
    print("[+] info_snh.db created (shared target database).")