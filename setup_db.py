#note that claude was used to generate this code, as we deemed generating the databases 
#not to be the best use of our time, and we wanted to focus on the attacks of the databases instead

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

# ---------------------------------------------------------------
# DATABASE 1 — login_vulnerable.db (Attack 1)
# Stores username + password in plaintext.
# Uses raw string concatenation in queries — wide open to SQLi.
# ---------------------------------------------------------------

def setup_login_vulnerable():
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

# ---------------------------------------------------------------
# DATABASE 2 — login_secure.db (Attack 2)
# Stores username + password in plaintext BUT uses parameterized
# queries, making classic OR '1'='1' injections ineffective.
# Still no hashing — so if data is leaked, passwords are exposed.
# ---------------------------------------------------------------

def setup_login_secure():
    conn = sqlite3.connect("db/login_secure.db")
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
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )

    conn.commit()
    conn.close()
    print("[+] login_secure.db created (Attack 2 — plaintext pw, parameterized queries).")

# ---------------------------------------------------------------
# DATABASE 3 — login_snh.db (Attacks 3 & 4)
# Stores username + salt + hash only. No plaintext password.
# Attack 3 tests second-order injection against this db.
# Attack 4 rehashes salt on detected breach (dynamic access control).
# ---------------------------------------------------------------

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

# --- Main ---

if __name__ == "__main__":
    os.makedirs("db", exist_ok=True)
    setup_login_vulnerable()
    setup_login_secure()
    setup_login_snh()
    setup_info_db()
    print("\n[+] All databases ready in /db")
    print("    login_vulnerable.db  -> Attack 1")
    print("    login_secure.db      -> Attack 2")
    print("    login_snh.db         -> Attacks 3 & 4")
    print("    info.db              -> Shared target (all attacks)")