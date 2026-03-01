# ♥ CharityHub — Donation Management System
### Programming II Project | University Antonine

---
<img width="1885" height="909" alt="image" src="https://github.com/user-attachments/assets/4b8794cc-c39d-4806-b13a-74cd3cadc8ac" />


## 🚀 Features

### Core Requirements ✅
- **User registration & login** with full validation
- **Admin panel**: Add, Remove, Modify charities
- **Donor panel**: Browse, Donate, View, Cancel, Modify donations
- **File persistence**: `users.txt`, `charities.txt`, `donations_<id>.txt`
- **Dynamic arrays & pointers** for all data structures
- **Sorting**: Merge sort by amount + date (ascending)
- **PDF Report**: HTML-based report (open in browser → Ctrl+P → Save as PDF)

### Bonus Features ✅
- **JSON database** (`data/database.json`) — bonus storage format
- **`ctime` library** for all date/time operations (no manual date struct)
- **Modern Web Dashboard** (`dashboard.html`) auto-generated with live charity data

### Security Features 🔐
| Feature | Implementation |
|---------|----------------|
| Password hashing | **SHA-256 + per-user random salt (PBKDF2-style, 10,000 iterations)** |
| Brute-force protection | Login locked after 5 failed attempts — **lockout persists across logout** |
| Session lockout | **60-second cooldown timer** — cannot be bypassed by logging out |
| Admin detection | `isAdmin` stored as **explicit flag in file** — never derived from name |
| Authorization | Donations validated for **ownership before any operation** |
| Buffer safety | Dynamic arrays use **capacity tracking + safe resize** — no overflow |
| Input sanitization | Removes dangerous chars before file storage |
| Email validation | Regex RFC 5322 simplified format check |
| Phone validation | Lebanese format `XX-XXXXXX` |
| Password policy | Min 8 chars, must include letters + digits + special chars |
| XSS prevention | HTML-escape all output written to web files |
| Memory safety | **Plaintext passwords wiped from memory** immediately after hashing |
| Timing attack prevention | **Constant-time password comparison** to prevent side-channel leaks |
| Information disclosure | Dashboard shows **only public stats** — no internal user data exposed |

---

## 📁 Project Structure

```
charity_project/
├── main.cpp              ← Complete C++ source code (secured)
├── Makefile              ← Build instructions
├── README.md             ← This file
├── dashboard.html        ← Generated web dashboard (auto-created)
└── data/
    ├── charities.txt     ← Charity data
    ├── users.txt         ← User accounts (SHA-256 hashed passwords)
    ├── donations.txt     ← Master donations log
    ├── donations_<id>.txt← Per-user donation files
    ├── database.json     ← JSON database (Bonus)
    └── report_<id>.html  ← Generated PDF reports
```

---

## ⚙️ Build & Run

```bash
# Compile
g++ -std=c++17 -Wall -o charityhub main.cpp

# OR use Makefile
make

# Run
./charityhub
```

**Requires:** GCC 7+ or Clang 5+ with C++17 support.

---

## 👤 Data Structures

```cpp
struct DateTime { string Date; string Time; };          // Uses ctime (Bonus)

struct Donation {
    int donationID; int charityID;
    double amount;  DateTime d;  string message;
};

struct Client {
    int userID; string firstName; string lastName;
    string password;  // ← stored as "salt:SHA256hash" — never plaintext
    string salt;      // ← per-user random 16-byte salt
    string phone; string email;
    int nbDonations; Donation *donations;   // ← dynamic array
    bool isAdmin;     // ← read from file explicitly — never derived from name
};

struct Charity {
    int charityID; string name; string description;
    double targetAmount; double currentAmount;
    DateTime deadline; string status;
};
```

---

## 🔐 Security Architecture

### Password Hashing (SHA-256 + Salt)
Passwords are **never stored in plaintext**. Each password is hashed using:
1. A **random 16-byte salt** generated via `/dev/urandom`
2. **10,000 iterations** of SHA-256 (PBKDF2-style) to slow brute-force attacks
3. Stored in `users.txt` as `salt:hash` — opaque token only

```
users.txt format:
userID firstName lastName salt:SHA256hash email phone isAdmin(0/1)
```

### Brute-Force Protection
- Locks after **5 failed login attempts**
- **60-second cooldown** before next attempt
- Lockout counter is a **global static variable** — survives logout/re-login cycles
- Attacker **cannot bypass lockout** by logging out and back in

### Admin Privilege Control
- `isAdmin` is stored as an **explicit integer (0 or 1)** in `users.txt`
- `registerUser()` always sets `isAdmin = false` — **no user input can grant admin**
- Admin status is **never inferred from username, email, or any string comparison**

---

## 🌐 Web Dashboard Integration

The app auto-generates `dashboard.html` on startup and after every logout:
- Live charity progress bars
- Stats (total raised, open campaigns)
- Responsive design (mobile-friendly)
- **Only public data exposed** — no user emails, names, or passwords in output

To view: **open `dashboard.html` in any web browser**.

---

## 📊 PDF Reports

Donor reports are generated as styled HTML → open in browser → `Ctrl+P` → Save as PDF.

Donations are **sorted by amount (ascending), then date** using Merge Sort O(n log n).

---

## 🔑 Test Accounts

| Role  | Email | Password |
|-------|-------|----------|
| Donor | zahi.chami@ua.edu.lb | (register to set) |
| Admin | admin@charityhub.com | (register to set) |
| Donor | john.smith@hotmail.com | (register to set) |

> **Note:** Passwords in `users.txt` are SHA-256 hashed with unique salts. Register a new account to test login properly.

---

## 📋 Evaluation Checklist

| Criterion | Status |
|-----------|--------|
| Understands project requirements | ✅ Complete |
| Dynamic memory allocation (no waste) | ✅ Capacity tracking + safe resize |
| Data structures + CRUD | ✅ All 4 operations on all entities |
| File read/write operations | ✅ TXT + JSON (Bonus) |
| Program correctness (tested) | ✅ All cases tested |
| Bonus: JSON/XML files | ✅ JSON implemented |
| Bonus: ctime library | ✅ Used throughout |
| Modern UI | ✅ Colored terminal + Web dashboard |
| Security: Password hashing | ✅ SHA-256 + salt (upgraded from XOR) |
| Security: Session management | ✅ Persistent lockout across logout |
| Security: Admin protection | ✅ Explicit flag — never name-derived |
| Security: Authorization | ✅ Ownership check on all donation ops |
| Security: XSS prevention | ✅ escapeHtml() on all web output |
| Security: Memory safety | ✅ Plaintext wiped after hashing |

---

*Good Luck at the Defense! 🎓*


