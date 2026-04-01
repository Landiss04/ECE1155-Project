# SQL Injection Demo — Simulated Banking System
**Landis Strohecker & Harry Tye**
University of Pittsburgh

---

## Overview

This project simulates a banking web application that is progressively hardened against SQL injection attacks. The system demonstrates 4 attacks of increasing sophistication, each targeting a different level of security, and implements 5 countermeasures to defend against them.

---

## Project Structure

```
project/
├── db/
│   ├── login_vulnerable.db   # Attack 1 — plaintext passwords, no parameterization
│   ├── login_secure.db       # Attack 2 — plaintext passwords, parameterized queries
│   ├── login_snh.db          # Attacks 3 & 4 — salt + hash, no plaintext password
│   └── info.db               # Shared target database (account info)
├── setup_db.py               # Populates all 4 databases with fake users
├── app/
│   ├──banking_app.py            # Simulated banking website (login + dashboard)
    ├── queries.py 
│   └──login.html               # All login query logic, one function per attack level
└── README.md
```

---

## Setup

### Requirements
- Python 3.x
- Flask (`pip install flask`)

No other dependencies are needed. SQLite3 is included in Python's standard library.

### Initialize the Databases
```bash
python setup_db.py
```
This will generate all 4 databases inside the `/db` folder.

### Run the App
```bash
python banking_app.py
```
Then navigate to `http://127.0.0.1:5000` in your browser.

---

## Databases

| Database | Columns | Used In |
|---|---|---|
| `login_vulnerable.db` | username, password | Attack 1 |
| `login_secure.db` | username, password | Attack 2 |
| `login_snh.db` | username, salt, hash | Attacks 3 & 4 |
| `info.db` | username, full_name, balance | All attacks (target) |

An attack is considered **successful** if any meaningful data from `info.db` is retrieved.

---

## Attacks

### Attack 1 — Simple SQL Injection
- **Target:** `login_vulnerable.db`
- **Method:** Basic `OR '1'='1'` injection via raw string concatenation
- **Tests:** Input validation countermeasure

### Attack 2 — SQL Injection with Valid Inputs
- **Target:** `login_secure.db`
- **Method:** Injection using only valid characters to bypass input filtering
- **Tests:** Parameterized queries countermeasure

### Attack 3 — Second Order SQL Injection
- **Target:** `login_snh.db`
- **Method:** Malicious input stored and later executed unsafely in a second query
- **Tests:** Hash & salt countermeasure

### Attack 4 — Second Order Injection + Hash Compromise
- **Target:** `login_snh.db`
- **Method:** Simulates a cracked hash, attempts cross-database access
- **Tests:** Dynamic access control countermeasure

---

## Countermeasures

1. **Input Validation** — Restricts user input to a safe set of characters
2. **Parameterized Queries** — Treats all user input as data, never as executable code
3. **Error Suppression** — Database errors are never exposed to the user
4. **Hash & Salt** — Passwords are never stored in plaintext; any leaked data is meaningless
5. **Dynamic Access Control** — On detected breach, credentials are rehashed and access to `info.db` is revoked until rehashing is complete

---

## Division of Work

| Task | Owner |
|---|---|
| SQL Databases & setup_db.py | Landis |
| Banking App UI (banking_app.py) | Landis |
| Query logic & attack implementations (queries.py, attacks.py) | Harry |
| Countermeasure design & testing | Harry |

---

## Test Users

The following fake users are pre-loaded into all databases:

| Username | Full Name | Balance |
|---|---|---|
| jsmith | John Smith | $12,500.75 |
| ajohnson | Alice Johnson | $98,200.00 |
| bwilliams | Bob Williams | $3,340.50 |
| mgarcia | Maria Garcia | $54,780.20 |
| tdavis | Tom Davis | $1,200.00 |
| swilson | Sarah Wilson | $23,100.60 |
| rmoore | Robert Moore | $8,750.30 |
| ltaylor | Laura Taylor | $67,000.00 |
| kanderson | Kevin Anderson | $15,500.90 |
| nthomas | Nancy Thomas | $4,400.10 |

> **Note:** Plaintext passwords are only visible in `login_vulnerable.db` and `login_secure.db`. In `login_snh.db` all passwords are replaced by a salt and SHA-256 hash.

---

## References

- [W3Schools — SQL Injection](https://www.w3schools.com/sql/sql_injection.asp)
- A. Rai et al., "SQL Injection: Classification and Prevention," ICIEM 2021
- S. Neupane, "Detecting and Mitigating SQL Injection Vulnerabilities in Web Applications," arXiv:2506.17245v1