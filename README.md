# SQL Injection Attacks and Countermeasures: A Simulated Banking System Case Study

**Authors:** Landis Strohecker (lrs126@pitt.edu) | Harry Tye (hit24@pitt.edu)  
**Institution:** University of Pittsburgh

---

## Abstract

This project presents a simulation of SQL injection attacks and countermeasures implemented within a mock banking web application. SQL injection attacks have become and continue to be a prevalent threat to many web-based applications. While simple countermeasures are able to prevent many of these attacks, the increasing amount of sensitive information contained within web applications has motivated malicious actors to develop more complex attacks. Our system attempts to illustrate these recent developments by demonstrating five attack scenarios of increasing sophistication:

1. **Basic boolean-based SQL injection** — The simplest attack using always-true conditions
2. **Input validation avoidant attack** — Bypasses input validation using alternative SQL syntax
3. **Second order injection** — A two-phase attack exploiting stored data
4. **Broken hash attack** — Simulation of brute-forced password hashing
5. **Comprehensive attack scenario** — Tests all countermeasures together

For each attack, a new countermeasure designed specifically to protect against the attack is implemented along with the previous countermeasures. The countermeasures include:

- **Input Validation** — Restricting user inputs to allowed character sets
- **Parameterized Queries** — Separating SQL code from user data
- **Hash & Salt** — Protecting password storage with cryptographic hashing
- **Dynamic credential rehashing** — Detecting and responding to breaches with automatic rehashing

The application is built using Python with Flask, backed by SQLite databases. Explicit testing is done for each attack and corresponding countermeasure in addition to a simulated real-time stream of attacks. Results demonstrate that **no single countermeasure is sufficient on its own**, and that **layered security is essential** to protecting sensitive user data.

---

## System Overview

Our system models a banking application using Python libraries like Flask and SQLite. The focus of this project is to simulate SQL injection vulnerabilities and defenses, so we opted for a simple interface with input boxes for username and password.

### Login Page
Users enter credentials to authenticate. On successful sign-in, users are redirected to a dashboard displaying their account balance. The login system uses SQL queries to validate credentials against a database, which creates the vulnerabilities we exploit.

### Dashboard
After authentication, users see a page displaying their account balance. In a real banking application, additional confidential information would be displayed, but for this project, account balance is sufficient.

---

## Attack Model

**Structured Query Language (SQL)** is a popular programming language used for database management. SQL functions by populating and accessing data through developer-crafted queries. These queries check database entries for matching keys and apply specific actions to matching results.

In our login system, a SQL query compares user-supplied username and password against values in the database. If both match, the user is logged in. Without proper protections, however, this query structure creates vulnerabilities that can be exploited.

### Attack 1: Basic Boolean-Based Injection

The simplest attack crafts an input containing a boolean expression that is always true (e.g., `' OR '1'='1`). This manipulation causes the SQL query to always return true, granting unauthorized access to any account.

**Example:** Using a password of `' OR '1'='1` allows login without knowing the real password.

### Attack 2: Input Validation Avoidant Attack

Attack 2 uses the same boolean exploitation technique as Attack 1, but it bypasses **input validation** countermeasures. If input validation prevents spaces and quotes, an attacker can use alternative syntax like parentheses and dashes (e.g., `(--(space)1)=1`) to craft the same always-true condition.

**Key insight:** Input validation must fit the application context and can still allow malicious characters if not comprehensive.

### Attack 3: Second Order Injection

This two-phase attack represents a conceptual break from Attacks 1 and 2:

1. **Phase 1:** The attacker registers a legitimate account with non-malicious inputs
2. **Phase 2:** The attacker abuses a legitimate feature (e.g., update username) to inject malicious SQL that executes later

In our system, this attack exploits the username-change feature to execute a SQL injection that provides access to other users' credentials or enables denial-of-service attacks.

### Attack 4: Broken Hash Attack

Attack 4 does not focus on SQL injection itself. Instead, it simulates an attacker who has successfully compromised the password hashing function (brute-forced or stolen the hash algorithm). This tests overall system security in a worst-case scenario where the attacker can generate valid password hashes.

### Attack 5: Comprehensive Attack Scenario

Attack 5 tests all countermeasures together against a simulated real-time stream of attacks, measuring success rates and system downtime.

---

## Countermeasures

Each countermeasure is designed to address one of the attacks and is implemented alongside previous countermeasures, creating **layered defense**.

### Countermeasure 1: Input Validation

Restricts user inputs to an allowed set of characters, preventing malicious SQL syntax characters from being submitted. If implemented correctly, input validation can be very effective, but it must be context-appropriate (e.g., passwords cannot be limited to only alphabetic characters).

### Countermeasure 2: Parameterized Queries

One of the most widely-used SQL injection defenses. User inputs are treated as discrete parameters separate from the SQL query itself, preventing the SQL backend from interpreting user data as executable code.

**Example:**
```sql
-- Vulnerable: SELECT * FROM users WHERE username='{input}'
-- Secure: SELECT * FROM users WHERE username=?  (with input as separate parameter)
```

### Countermeasure 3: Hash & Salt

Passwords are not stored as plaintext. Instead, when a user signs up, a unique salt value is generated for each password. The password is hashed together with the salt and username, and only the hash and salt are stored. This prevents second-order injections from revealing meaningful password information.

### Countermeasure 4: Dynamic Credential Rehashing

If a breach is detected (compromised hashing function), the system automatically rehashes all credentials with a new hash function and denies access to users during the rehashing process. In our system, rehashing is triggered manually, but in practice, this would be part of breach detection.

---

## Project Structure

```
ECE1155-Project/
├── app/
│   ├── banking_app.py          # Flask application (login + dashboard pages)
│   ├── attacks.py              # Attack simulation logic
│   ├── setup_db.py             # Database initialization script
│   └── templates/
│       ├── login.html          # Login page
│       └── dashboard.html      # Dashboard page (post-login)
├── db/                         # SQLite databases (created on first run)
│   ├── login_vulnerable.db     # Level 1: No protections
│   ├── login_input_val.db      # Level 2: Input validation
│   ├── login_parameterized.db  # Level 3: Parameterized queries
│   ├── login_hash_salt.db      # Level 4: Hash & salt
│   └── login_secure.db         # Level 5: Full protections + rehashing
└── README.md
```

---

## Setup & Running the Application

### Requirements

- **Python 3.x**
- **Flask** (`pip install flask`)

SQLite3 is included in Python's standard library, so no additional database software is needed.

### Step 1: Initialize the Databases

```bash
python setup_db.py
```

This script populates all SQL databases in the `/db` folder with fake user credentials and account information.

### Step 2: Run the Application

```bash
python banking_app.py
```

The Flask application will start on `http://127.0.0.1:5000`. Open this URL in your web browser.

### Step 3: Test Different Security Levels

Upon login, you can select different security levels (1-5) to test attacks against different countermeasure configurations:

- **Level 1:** Vulnerable — no protections
- **Level 2:** Input validation applied
- **Level 3:** Parameterized queries applied
- **Level 4:** Hash & salt applied
- **Level 5:** All countermeasures + dynamic rehashing

### Step 4: Simulate Attacks

The `attacks.py` module contains attack simulation functions that test each security level with the five attack scenarios.

---

## Results & Findings

### Attack Success Rates

Testing shows the effectiveness of layered security:

- **Level 1 (Vulnerable):** Basic and sophisticated attacks succeed
- **Level 2 (Input Validation):** Basic attacks blocked, some escape attack vectors still work
- **Level 3 (Parameterized Queries):** Attacks 1 & 2 completely blocked
- **Level 4 (Hash & Salt):** Second-order injection attacks produce no useful information
- **Level 5 (Full Security):** Comprehensive attack simulation shows all attacks blocked

### System Downtime

Dynamic credential rehashing (Countermeasure 4) incurs minimal system downtime: approximately **0.0053 seconds**, which is negligible for practical purposes.

### Key Takeaway

**No single countermeasure is sufficient on its own.** Each attack found a way around previous defenses, demonstrating that layered security is essential. The combination of input validation, parameterized queries, password hashing, and breach response creates a resilient defense against SQL injection.

---

## Conclusions

This project demonstrates that SQL injection is a serious and evolving threat requiring multi-layered defense strategies. Through five attacks of increasing sophistication, we showed that:

1. **Layered security is essential** — Each countermeasure addresses specific vulnerabilities
2. **Context matters** — Input validation must be appropriate to the application
3. **Defense-in-depth works** — Combining multiple defenses is far more effective than any single approach
4. **Regular updates are critical** — As attack methods evolve, countermeasures must also adapt

While our system is a simplified version of real-world banking applications, the vulnerabilities and countermeasures explored reflect genuine security challenges that developers must account for when building applications handling sensitive data.

---

## References

1. W3Schools. "SQL Injection." https://www.w3schools.com/sql/sql_injection.asp
2. A. Rai, M. M. I. Miraz, D. Das, H. Kaur and Swati, "SQL Injection: Classification and Prevention," 2021 2nd International Conference on Intelligent Engineering and Management (ICIEM), London, United Kingdom, 2021, pp. 367-372, doi: 10.1109/ICIEM51511.2021.9445347.
3. S. Neupane, "Detecting and Mitigating SQL Injection Vulnerabilities in Web Applications", arXiv:2506.17245v1, University of West London, Ealing, United Kingdom.

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