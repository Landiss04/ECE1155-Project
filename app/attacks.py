import sqlite3
import hashlib
import time
import random

from setup_db import ATTACK_LOG, INFO_LOG, is_valid_password, is_valid_username, access_info_db, update_username
from setup_db import LOGIN_DB, LOGIN_SNH
from setup_db import hash_password, verify_password

# Usernames & passwords for each level of attack
ATTACK_USERNAMES = [
    "' OR '1'='1",       # Basic injection for Attack 1
    "attacker" # Legitimate username for second order injection
]

ATTACK_PASSWORDS = [
    "' OR '1'='1",       # Basic injection for Attack 1
    "'OR(1=1)--",    # Sophisticated injection bypassing simple input checks for Attack 2
    "password123",  # Matching password with jsmith for second order injection in Attack 3
    "",
    "",
]

# Simpler attacks are more common
ATTACK_WEIGHTS = [
    (1, 50),   
    (2, 30),   
    (3, 15),   
    (4, 4),   
    (5, 1), 
]

def login1(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_DB)
    cur = conn.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';"
    cur.execute(query)
    result = cur.fetchone()
    conn.close()

    if result:
        INFO_LOG.append((username, password))
        return access_info_db(username)
    return False

def login2(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_DB)
    cur = conn.cursor()

    test = is_valid_username(username)
    test1 = is_valid_password(password)
    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Input validation blocked: {username}")
        return False

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';"
    cur.execute(query)
    result = cur.fetchone()
    conn.close()

    if result:
        retrieved_username = result[1]
        INFO_LOG.append((username, password))
        return access_info_db(retrieved_username)
    return False

def login3(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_DB)  # parameterized DB
    cur = conn.cursor()

    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Input validation blocked: {username}")
        return False

    query = "SELECT * FROM users WHERE username = ? AND password = ?;"
    cur.execute(query, (username, password))
    result = cur.fetchone()
    if not result and username == ATTACK_USERNAMES[1] and password == ATTACK_PASSWORDS[2]:
        ATTACK_LOG.append(f"Failed parameterized login: {username}")

        # Add user to database since safe inputs
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        # Perform second order injection by updating username to attack payload
        update_username(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[2], ATTACK_USERNAMES[1])
        return access_info_db(ATTACK_USERNAMES[0])
    else:        
        ATTACK_LOG.append(f"Failed parameterized login: {username}")
    return False

def login4(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_SNH)  # salt and hash DB
    cur = conn.cursor()

    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Input validation blocked: {username}")
        return False

    # Fetch stored salt and hash for this username
    cur.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and verify_password(password, row[1], row[0]):
        INFO_LOG.append((username, password))
        update_username(username, ATTACK_PASSWORDS[2])
        return access_info_db(username)
    else:
        ATTACK_LOG.append(f"Failed salt/hash login: {username}")
    return False

def login5(username: str, password: str) -> bool:
    conn = sqlite3.connect(LOGIN_SNH)
    cur = conn.cursor()

    if not is_valid_username(username) or not is_valid_password(password):
        ATTACK_LOG.append(f"Blocked invalid input for user: {username}")
        print(f"[-] Input validation blocked: {username}")
        return False

    cur.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if row and verify_password(password, row[1], row[0]):
        INFO_LOG.append((username, password))

        # Rehash all with new salt
        print("[!] Breach detected — initiating dynamic access control...")
        start_time = time.time()

        new_salt = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]  # random new salt
        conn = sqlite3.connect(LOGIN_SNH)
        cur = conn.cursor()

        # Get all plaintext passwords
        cur.execute("SELECT username, plaintext_password FROM users")
        users = cur.fetchall()

        for uname, plaintext in users:
            new_hash = hash_password(plaintext, new_salt)
            cur.execute(
                "UPDATE users SET password = ?, salt = ? WHERE username = ?",
                (new_hash, new_salt, uname)
            )

        conn.commit()
        conn.close()

        end_time = time.time()
        global TIME_DOWN
        TIME_DOWN += end_time - start_time
        print(f"[+] Rehash complete in {end_time - start_time:.4f}s — second order payloads invalidated.")

        return access_info_db(username)
    else:
        ATTACK_LOG.append(f"Failed breach detection login: {username}")
    return False

# Attack functions 
def attack1() -> bool:
    result = login1(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0])
    print(f"  [Attack 1] Basic injection {'succeeded' if result else 'failed'}")
    return result

def attack2() -> bool:
    result1 = login2(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0])
    print(f"  [Attack 2a] Basic injection with validation: {'succeeded' if result1 else 'blocked'}")

    result2 = login2(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[1])
    print(f"  [Attack 2b] Sophisticated bypass ('OR(1=1)--): {'succeeded' if result2 else 'blocked'}")

    return result1 or result2

def attack3() -> bool:
    result1 = login3(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0])
    print(f"  [Attack 3a] Basic injection with parameterization: {'succeeded' if result1 else 'blocked'}")

    result2 = login3(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[1])
    print(f"  [Attack 3b] Sophisticated bypass with parameterization: {'succeeded' if result2 else 'blocked'}")

    result3 = login3(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[2])
    print(f"  [Attack 3c] Second order injection: {'succeeded' if result3 else 'failed'}")

    return result1 or result2 or result3

def attack4() -> bool:
    result1 = login4(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0])
    print(f"  [Attack 4a] Basic injection on hashed DB: {'succeeded' if result1 else 'blocked'}")

    result2 = login4(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[2])
    print(f"  [Attack 4b] Second order on hashed DB: {'succeeded' if result2 else 'failed'}")

    return result1 or result2

def attack5() -> bool:
    result1 = login5(ATTACK_USERNAMES[0], ATTACK_PASSWORDS[0])
    print(f"  [Attack 5a] Basic injection with breach detection: {'succeeded' if result1 else 'blocked'}")

    result2 = login5(ATTACK_USERNAMES[1], ATTACK_PASSWORDS[2])
    print(f"  [Attack 5b] Second order with breach detection + rehash: {'succeeded' if result2 else 'invalidated'}")

    return result1 or result2


TIME_DOWN = 0.0
ATTACK_FUNCTIONS = {
    1: attack1,
    2: attack2,
    3: attack3,
    4: attack4,
    5: attack5,
}

def real_time_attack(num_attacks: int = 20, delay: float = 0.5):
    
    attack_numbers = [a for a, _ in ATTACK_WEIGHTS]
    weights        = [w for _, w in ATTACK_WEIGHTS]

    print(f"\n{'='*50}")
    print(f"Starting real-time attack simulation ({num_attacks} attacks)")
    print(f"{'='*50}\n")

    for i in range(num_attacks):
        # Weighted random selection — simpler attacks more likely
        chosen = random.choices(attack_numbers, weights=weights, k=1)[0]
        attack_fn = ATTACK_FUNCTIONS[chosen]

        print(f"[{i+1}/{num_attacks}] Launching Attack {chosen}...")
        success = attack_fn()

        time.sleep(delay)

    # Display logs
    print(f"\n{'='*50}")
    print("Attack Log:")
    for entry in ATTACK_LOG:
        print(f"  - {entry}")   
    print(f"\n{'='*50}")
    print("Info Log (successful accesses):")
    for username, password in INFO_LOG:
        print(f"  - Username: {username}, Password: {password}")
    print(f"\nTotal system downtime from rehashing: {TIME_DOWN:.4f}s")


def main():
    print("Running Attack 1...")
    print(f"Attack 1 successful: {attack1()}\n")

    print("Running Attack 2...")
    print(f"Attack 2 successful: {attack2()}\n")

    print("Running Attack 3...")
    print(f"Attack 3 successful: {attack3()}\n")

    print("Running Attack 4...")
    print(f"Attack 4 successful: {attack4()}\n")

    print("Running Attack 5...")
    print(f"Attack 5 successful: {attack5()}\n")

    print("Running real-time simulation...")
    real_time_attack(num_attacks=20, delay=0.5)

if __name__ == "__main__":
    main()