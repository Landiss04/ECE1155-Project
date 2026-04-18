# SQL Injection Attacks and Countermeasures: A Simulated Banking System Case Study

**Authors:** Landis Strohecker (lrs126@pitt.edu) | Harry Tye (hit24@pitt.edu)  
**Institution:** University of Pittsburgh

---

## Overview

This project simulates a banking web application that demonstrates SQL injection vulnerabilities and progressive security countermeasures. The system implements five attack scenarios and four defense mechanisms using Python, Flask, and SQLite databases.

---

## Quick Start

### Requirements

- **Python 3.x**
- **Flask** (`pip install flask`)

### Installation & Execution

1. **Initialize the databases:**
   ```bash
   python setup_db.py
   ```

2. **Start the web application:**
   ```bash
   python banking_app.py
   ```
   Navigate to `http://127.0.0.1:5000` in your browser. Test the login with username `jsmith` and password `password123`.

3. **Run the attack simulations:**
   ```bash
   python attacks.py
   ```
   This script runs all five attack scenarios against each security level and logs results.

---

## Project Structure

```
ECE1155-Project/
├── app/
│   ├── banking_app.py          # Flask application (login + dashboard)
│   ├── attacks.py              # Attack simulation script (RUN THIS)
│   ├── setup_db.py             # Database initialization
│   └── templates/
│       ├── login.html
│       └── dashboard.html
├── db/                         # SQLite databases (auto-created)
├── README.md
```

---
