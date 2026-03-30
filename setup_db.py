#note that we used Claude to populate the databases with fake user data as this was a time consuming task and we wanted to focus on the security aspects of the project. 
#The code below is what we used to generate the databases with the fake user data.

import sqlite3
import hashlib
import os

# --- Helpers ---

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

# --- Build login.db ---

def setup_login_db():
    conn = sqlite3.connect("db/login.db")
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            salt     TEXT    NOT NULL,
            hash     TEXT    NOT NULL
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
    print("[+] login.db created and populated.")

# --- Build info.db ---

def setup_info_db():
    conn = sqlite3.connect("db/info.db")
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("""
        CREATE TABLE accounts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE,
            full_name  TEXT    NOT NULL,
            balance    REAL    NOT NULL
        )
    """)

    for username, _, full_name, balance in USERS:
        cur.execute(
            "INSERT INTO accounts (username, full_name, balance) VALUES (?, ?, ?)",
            (username, full_name, balance)
        )

    conn.commit()
    conn.close()
    print("[+] info.db created and populated.")

# --- Main ---

if __name__ == "__main__":
    os.makedirs("db", exist_ok=True)
    setup_login_db()
    setup_info_db()
    print("[+] Both databases ready in /db")