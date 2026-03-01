/*
 * ============================================================
 *  CHARITY DONATION MANAGEMENT SYSTEM
 *  Programming II Project - University Antonine
 *  Features: Full CRUD, JSON storage (Bonus), ctime (Bonus),
 *            Password hashing (SHA-256 + Salt), Input validation,
 *            PDF report generation, Web dashboard integration
 *
 *  SECURITY FIXES APPLIED:
 *  [FIX-1] Weak XOR hash replaced with SHA-256 + per-user salt (PBKDF2-style)
 *  [FIX-2] Sensitive data files: passwords stored as "salt:hash" never plaintext
 *  [FIX-3] Admin detection: isAdmin stored explicitly in file, never derived from name
 *  [FIX-4] Authorization: all donation ops validate ownership before execution
 *  [FIX-5] Buffer overflow: dynamic array resize checks capacity before every add
 *  [FIX-6] Session management: lockout counter never resets on logout
 *  [FIX-7] Information disclosure: dashboard shows no internal stats without auth
 * ============================================================
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <ctime>
#include <cmath>
#include <regex>
#include <algorithm>
#include <iomanip>
#include <limits>
#include <vector>
#include <stdexcept>
#include <random>       // FIX-1: for salt generation
#include <functional>   // FIX-1: for SHA-256
#include <chrono>       // FIX-1: for entropy seed

using namespace std;

// ─────────────────────────────────────────────
//  COLOR CODES FOR MODERN TERMINAL UI
// ─────────────────────────────────────────────
#define RESET    "\033[0m"
#define BOLD     "\033[1m"
#define RED      "\033[31m"
#define GREEN    "\033[32m"
#define YELLOW   "\033[33m"
#define BLUE     "\033[34m"
#define MAGENTA  "\033[35m"
#define CYAN     "\033[36m"
#define WHITE    "\033[37m"
#define BG_BLUE  "\033[44m"
#define BG_GREEN "\033[42m"

// ─────────────────────────────────────────────
//  STRUCTURES
// ─────────────────────────────────────────────

struct DateTime {
    string Date;  // DD-MM-YYYY
    string Time;  // HH:MM
};

struct Donation {
    int    donationID;
    int    charityID;
    double amount;
    DateTime d;
    string message;
};

struct Client {
    int      userID;
    string   firstName;
    string   lastName;
    string   password;   // [FIX-1] stored as "salt:SHA256hash" — never plaintext
    string   salt;       // [FIX-1] per-user random salt
    string   email;
    string   phone;
    int      nbDonations;
    Donation *donations;
    bool     isAdmin;    // [FIX-3] stored in file explicitly, never derived from name
};

struct Charity {
    int    charityID;
    string name;
    string description;
    double targetAmount;
    double currentAmount;
    DateTime deadline;
    string status;
};

// ─────────────────────────────────────────────
//  GLOBAL DATA
// ─────────────────────────────────────────────
const string DATA_DIR       = "data/";
const string USERS_FILE     = DATA_DIR + "users.txt";
const string CHARITIES_FILE = DATA_DIR + "charities.txt";
const string DONATIONS_FILE = DATA_DIR + "donations.txt";
const string JSON_FILE      = DATA_DIR + "database.json";
const string WEB_DASHBOARD  = "dashboard.html";

// ─────────────────────────────────────────────
//  [FIX-1] SECURE HASHING — SHA-256 + per-user salt
//  Pure C++ implementation (no OpenSSL required)
//  For real production: use libsodium argon2id instead
// ─────────────────────────────────────────────

// SHA-256 constants
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

string sha256(const string &input) {
    // Pre-processing: adding padding bits
    vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bitLen = (uint64_t)msg.size() * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back((bitLen >> (i * 8)) & 0xFF);

    // Initial hash values
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    // Process each 512-bit (64-byte) chunk
    for (size_t i = 0; i < msg.size(); i += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; ++j)
            w[j] = ((uint32_t)msg[i+j*4]<<24)|((uint32_t)msg[i+j*4+1]<<16)|
                   ((uint32_t)msg[i+j*4+2]<<8)|(uint32_t)msg[i+j*4+3];
        for (int j = 16; j < 64; ++j) {
            uint32_t s0 = rotr32(w[j-15],7) ^ rotr32(w[j-15],18) ^ (w[j-15]>>3);
            uint32_t s1 = rotr32(w[j-2],17) ^ rotr32(w[j-2],19)  ^ (w[j-2]>>10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int j = 0; j < 64; ++j) {
            uint32_t S1    = rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
            uint32_t ch    = (e&f)^(~e&g);
            uint32_t temp1 = hh+S1+ch+SHA256_K[j]+w[j];
            uint32_t S0    = rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
            uint32_t maj   = (a&b)^(a&c)^(b&c);
            uint32_t temp2 = S0+maj;
            hh=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    // Produce the final hash value (big-endian)
    ostringstream oss;
    for (int i = 0; i < 8; ++i)
        oss << hex << setfill('0') << setw(8) << h[i];
    return oss.str();
}

// Generate a cryptographically random 16-byte hex salt
string generateSalt() {
    // Use /dev/urandom if available (Linux/Mac), fallback to time+rand
    string salt(32, '0');
    ifstream urandom("/dev/urandom", ios::binary);
    if (urandom) {
        unsigned char buf[16];
        urandom.read(reinterpret_cast<char*>(buf), 16);
        ostringstream oss;
        for (int i = 0; i < 16; ++i)
            oss << hex << setfill('0') << setw(2) << (int)buf[i];
        salt = oss.str();
    } else {
        // Fallback: combine multiple sources of entropy
        mt19937_64 rng(chrono::steady_clock::now().time_since_epoch().count() ^ (uint64_t)clock());
        uniform_int_distribution<uint64_t> dist;
        ostringstream oss;
        oss << hex << setfill('0') << setw(16) << dist(rng) << setw(16) << dist(rng);
        salt = oss.str();
    }
    return salt;
}

// Hash password with salt using multiple SHA-256 rounds (PBKDF2-style, 10000 iterations)
string hashPasswordWithSalt(const string &password, const string &salt) {
    string result = salt + password;
    // 10,000 iterations to slow down brute-force attacks
    for (int i = 0; i < 10000; ++i)
        result = sha256(result + salt);
    return result;
}

// Verify password against stored "salt:hash"
bool verifyPassword(const string &password, const string &stored) {
    size_t sep = stored.find(':');
    if (sep == string::npos) return false;
    string salt = stored.substr(0, sep);
    string hash = stored.substr(sep + 1);
    string computed = hashPasswordWithSalt(password, salt);
    // Constant-time comparison to prevent timing attacks
    if (computed.size() != hash.size()) return false;
    volatile int diff = 0;
    for (size_t i = 0; i < computed.size(); ++i)
        diff |= (computed[i] ^ hash[i]);
    return diff == 0;
}

// Store format: "salt:hash"
string makePasswordHash(const string &password) {
    string salt = generateSalt();
    string hash = hashPasswordWithSalt(password, salt);
    return salt + ":" + hash;
}

// ─────────────────────────────────────────────
//  [FIX-6] GLOBAL LOGIN COUNTER — never reset on logout
//  Persists for the entire program session
// ─────────────────────────────────────────────
static int  g_loginAttempts = 0;
static bool g_locked        = false;
static time_t g_lockUntil   = 0;
const int MAX_ATTEMPTS      = 5;
const int LOCKOUT_SECONDS   = 60; // 60-second lockout after 5 failures

// ─────────────────────────────────────────────
//  VALIDATION FUNCTIONS
// ─────────────────────────────────────────────

bool isValidEmail(const string &email) {
    regex pattern(R"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})");
    return regex_match(email, pattern);
}

bool isValidPhone(const string &phone) {
    regex pattern(R"(\d{2}-\d{6})");
    return regex_match(phone, pattern);
}

bool isValidPassword(const string &pw) {
    if (pw.size() < 8) return false;
    bool hasLetter = false, hasDigit = false, hasSpecial = false;
    for (char c : pw) {
        if (isalpha(c))  hasLetter  = true;
        if (isdigit(c))  hasDigit   = true;
        if (ispunct(c))  hasSpecial = true;
    }
    return hasLetter && hasDigit && hasSpecial;
}

bool isValidDate(const string &date) {
    regex pattern(R"(\d{2}[\/\-]\d{2}[\/\-]\d{4})");
    return regex_match(date, pattern);
}

// [FIX-4] Sanitize input — strip dangerous characters
string sanitize(const string &input) {
    string out;
    for (char c : input) {
        if (isalnum(c) || c == ' ' || c == '-' || c == '_' ||
            c == '.'  || c == '@' || c == '+' || c == '!'  ||
            c == '#'  || c == '$' || c == '%' || c == '&'  ||
            c == '*'  || c == '(' || c == ')' || c == ','  ||
            c == '/'  || c == ':')
            out += c;
    }
    return out;
}

// [FIX-7] Escape HTML for all web output — prevent XSS in dashboard
string escapeHtml(const string &s) {
    string result;
    for (char c : s) {
        switch (c) {
            case '&':  result += "&amp;";  break;
            case '<':  result += "&lt;";   break;
            case '>':  result += "&gt;";   break;
            case '"':  result += "&quot;"; break;
            case '\'': result += "&#39;";  break;
            default:   result += c;
        }
    }
    return result;
}

// ─────────────────────────────────────────────
//  CTIME UTILITIES
// ─────────────────────────────────────────────

DateTime getCurrentDateTime() {
    time_t now = time(nullptr);
    tm *lt = localtime(&now);
    char dateBuf[11], timeBuf[6];
    strftime(dateBuf, sizeof(dateBuf), "%d-%m-%Y", lt);
    strftime(timeBuf, sizeof(timeBuf), "%H:%M",    lt);
    return { string(dateBuf), string(timeBuf) };
}

string dateTimeToString(const DateTime &dt) {
    return dt.Date + " " + dt.Time;
}

bool dateLessThan(const DateTime &a, const DateTime &b) {
    auto parse = [](const string &s, int &d, int &m, int &y) {
        sscanf(s.c_str(), "%d-%d-%d", &d, &m, &y);
    };
    int d1,m1,y1,d2,m2,y2;
    parse(a.Date, d1, m1, y1);
    parse(b.Date, d2, m2, y2);
    if (y1 != y2) return y1 < y2;
    if (m1 != m2) return m1 < m2;
    return d1 < d2;
}

// ─────────────────────────────────────────────
//  CHARITY CRUD
// ─────────────────────────────────────────────

Charity *charities    = nullptr;
int      charityCount = 0;

void loadCharities() {
    ifstream fin(CHARITIES_FILE);
    if (!fin) return;

    int count = 0;
    string line;
    while (getline(fin, line)) if (!line.empty()) count++;
    fin.clear(); fin.seekg(0);

    delete[] charities;
    charities    = new Charity[count];
    charityCount = 0;

    while (getline(fin, line)) {
        if (line.empty()) continue;
        istringstream ss(line);
        Charity &c = charities[charityCount++];
        string targetStr, currentStr;
        ss >> c.charityID >> c.name >> c.description
           >> targetStr >> currentStr
           >> c.deadline.Date >> c.deadline.Time >> c.status;
        targetStr.erase(remove(targetStr.begin(), targetStr.end(), '$'), targetStr.end());
        currentStr.erase(remove(currentStr.begin(), currentStr.end(), '$'), currentStr.end());
        try {
            c.targetAmount  = stod(targetStr);
            c.currentAmount = stod(currentStr);
        } catch (...) {
            c.targetAmount = c.currentAmount = 0;
        }
    }
    fin.close();
}

void saveCharities() {
    ofstream fout(CHARITIES_FILE);
    for (int i = 0; i < charityCount; i++) {
        Charity &c = charities[i];
        fout << c.charityID    << " "
             << c.name         << " "
             << c.description  << " "
             << fixed << setprecision(0) << c.targetAmount  << " "
             << c.currentAmount << " "
             << c.deadline.Date << " "
             << c.deadline.Time << " "
             << c.status        << "\n";
    }
    fout.close();
}

bool charityExists(const string &name) {
    for (int i = 0; i < charityCount; i++)
        if (charities[i].name == name) return true;
    return false;
}

int getNextCharityID() {
    int maxID = 100;
    for (int i = 0; i < charityCount; i++)
        if (charities[i].charityID > maxID) maxID = charities[i].charityID;
    return maxID + 1;
}

void addCharity() {
    Charity nc;
    cout << CYAN << "\n  ╔══════════════════════════════╗\n";
    cout <<          "  ║      ADD CHARITY CAMPAIGN     ║\n";
    cout <<          "  ╚══════════════════════════════╝\n" << RESET;

    cout << YELLOW << "  Name (no spaces, use _): " << RESET;
    cin >> nc.name;
    nc.name = sanitize(nc.name);

    if (nc.name.empty() || nc.name.size() > 100) {
        cout << RED << "  ✗ Invalid name!\n" << RESET; return;
    }
    if (charityExists(nc.name)) {
        cout << RED << "  ✗ Charity already exists!\n" << RESET; return;
    }

    cout << YELLOW << "  Description (no spaces, use _): " << RESET;
    cin >> nc.description;
    nc.description = sanitize(nc.description);

    cout << YELLOW << "  Target Amount ($): " << RESET;
    if (!(cin >> nc.targetAmount) || nc.targetAmount <= 0) {
        cout << RED << "  ✗ Invalid amount!\n" << RESET;
        cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
        return;
    }
    nc.currentAmount = 0;

    string dl;
    cout << YELLOW << "  Deadline (DD/MM/YYYY): " << RESET;
    cin >> dl;
    while (!isValidDate(dl)) {
        cout << RED << "  Invalid date! (DD/MM/YYYY): " << RESET;
        cin >> dl;
    }
    nc.deadline.Date = dl;
    cout << YELLOW << "  Deadline Time (HH:MM): " << RESET;
    cin >> nc.deadline.Time;
    nc.status    = "Open";
    nc.charityID = getNextCharityID();

    // [FIX-5] Safe array expansion
    Charity *tmp = new Charity[charityCount + 1];
    for (int i = 0; i < charityCount; i++) tmp[i] = charities[i];
    tmp[charityCount] = nc;
    delete[] charities;
    charities = tmp;
    charityCount++;

    saveCharities();
    cout << GREEN << "\n  ✓ Charity added! ID = " << nc.charityID << "\n" << RESET;
}

void removeCharity() {
    cout << CYAN << "\n  Remove Charity\n" << RESET;
    int id;
    cout << YELLOW << "  Enter Charity ID to remove: " << RESET;
    if (!(cin >> id)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(),'\n'); return; }

    int idx = -1;
    for (int i = 0; i < charityCount; i++)
        if (charities[i].charityID == id) { idx = i; break; }

    if (idx == -1) { cout << RED << "  ✗ Charity not found!\n" << RESET; return; }

    Charity *tmp = new Charity[charityCount - 1];
    for (int i = 0, j = 0; i < charityCount; i++)
        if (i != idx) tmp[j++] = charities[i];
    delete[] charities;
    charities = tmp;
    charityCount--;

    saveCharities();
    cout << GREEN << "  ✓ Charity removed!\n" << RESET;
}

void modifyCharity() {
    cout << CYAN << "\n  Modify Charity\n" << RESET;
    int id;
    cout << YELLOW << "  Enter Charity ID to modify: " << RESET;
    if (!(cin >> id)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(),'\n'); return; }

    Charity *c = nullptr;
    for (int i = 0; i < charityCount; i++)
        if (charities[i].charityID == id) { c = &charities[i]; break; }

    if (!c) { cout << RED << "  ✗ Not found!\n" << RESET; return; }

    cout << "\n  What to modify?\n"
         << "  [1] Name\n  [2] Description\n  [3] Target Amount\n"
         << "  [4] Current Amount\n  [5] Status\n  [6] Deadline\n";
    int choice; cin >> choice;

    string tmp;
    switch (choice) {
        case 1:
            cout << "  New name: "; cin >> tmp;
            c->name = sanitize(tmp); break;
        case 2:
            cout << "  New description: "; cin >> tmp;
            c->description = sanitize(tmp); break;
        case 3: {
            double val;
            cout << "  New target ($): ";
            if (cin >> val && val > 0) c->targetAmount = val;
            break;
        }
        case 4: {
            double val;
            cout << "  New current ($): ";
            if (cin >> val && val >= 0) c->currentAmount = val;
            break;
        }
        case 5:
            cout << "  New status (Open/Closed): "; cin >> tmp;
            if (tmp == "Open" || tmp == "Closed") c->status = tmp;
            break;
        case 6:
            cout << "  New deadline (DD/MM/YYYY): "; cin >> tmp;
            if (isValidDate(tmp)) c->deadline.Date = tmp;
            cout << "  New time (HH:MM): "; cin >> c->deadline.Time; break;
        default: cout << RED << "  Invalid choice!\n" << RESET; return;
    }
    saveCharities();
    cout << GREEN << "  ✓ Charity updated!\n" << RESET;
}

void browseCharities() {
    cout << CYAN << "\n  ╔═══════════════════════════════════════════════════════════════╗\n";
    cout <<          "  ║                    AVAILABLE CHARITIES                        ║\n";
    cout <<          "  ╚═══════════════════════════════════════════════════════════════╝\n" << RESET;

    bool found = false;
    for (int i = 0; i < charityCount; i++) {
        Charity &c = charities[i];
        if (c.status != "Open") continue;
        found = true;
        double pct = (c.targetAmount > 0) ? (c.currentAmount / c.targetAmount * 100.0) : 0;
        int bars = (int)(pct / 5);

        cout << "\n  " << BOLD << BLUE << "ID: " << c.charityID << " | " << c.name << RESET << "\n";
        cout << "  " << c.description << "\n";
        cout << "  Target: $" << fixed << setprecision(2) << c.targetAmount
             << " | Raised: $" << c.currentAmount
             << " | Deadline: " << c.deadline.Date << "\n";
        cout << "  Progress: [";
        for (int b = 0; b < 20; b++)
            cout << (b < bars ? GREEN "█" RESET : "░");
        cout << "] " << fixed << setprecision(1) << pct << "%\n";
    }
    if (!found) cout << YELLOW << "  No open charities currently.\n" << RESET;
}

// ─────────────────────────────────────────────
//  DONATION MANAGEMENT
// ─────────────────────────────────────────────

int globalDonations = 0;

void loadDonationsForUser(Client &client) {
    string fname = DATA_DIR + "donations_" + to_string(client.userID) + ".txt";
    ifstream fin(fname);
    if (!fin) { client.nbDonations = 0; client.donations = nullptr; return; }

    int count = 0;
    string line;
    while (getline(fin, line)) if (!line.empty()) count++;
    fin.clear(); fin.seekg(0);

    delete[] client.donations;
    client.donations   = new Donation[count];
    client.nbDonations = 0;

    while (getline(fin, line)) {
        if (line.empty()) continue;
        Donation &dn = client.donations[client.nbDonations++];
        istringstream ss(line);
        string amtStr;
        ss >> dn.donationID >> dn.charityID >> amtStr >> dn.d.Date >> dn.d.Time;
        amtStr.erase(remove(amtStr.begin(), amtStr.end(), '$'), amtStr.end());
        try { dn.amount = stod(amtStr); } catch (...) { dn.amount = 0; }
        if (ss.peek() != EOF) getline(ss, dn.message);
        if (!dn.message.empty() && dn.message[0] == ' ')
            dn.message = dn.message.substr(1);
    }
    fin.close();

    for (int i = 0; i < client.nbDonations; i++)
        if (client.donations[i].donationID > globalDonations)
            globalDonations = client.donations[i].donationID;
}

void saveDonationsForUser(Client &client) {
    string fname = DATA_DIR + "donations_" + to_string(client.userID) + ".txt";
    ofstream fout(fname);
    for (int i = 0; i < client.nbDonations; i++) {
        Donation &dn = client.donations[i];
        fout << dn.donationID << " " << dn.charityID << " "
             << fixed << setprecision(2) << dn.amount << " "
             << dn.d.Date << " " << dn.d.Time;
        if (!dn.message.empty()) fout << " " << dn.message;
        fout << "\n";
    }
    fout.close();
}

void makeDonation(Client &client) {
    browseCharities();

    int charID;
    cout << YELLOW << "\n  Enter Charity ID to donate to: " << RESET;
    if (!(cin >> charID)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(),'\n'); return; }

    Charity *target = nullptr;
    for (int i = 0; i < charityCount; i++)
        if (charities[i].charityID == charID && charities[i].status == "Open") {
            target = &charities[i]; break;
        }

    if (!target) { cout << RED << "  ✗ Charity not found or closed!\n" << RESET; return; }

    double amount;
    cout << YELLOW << "  Amount to donate ($): " << RESET;
    if (!(cin >> amount) || amount <= 0) {
        cout << RED << "  ✗ Invalid amount!\n" << RESET;
        cin.clear(); cin.ignore(numeric_limits<streamsize>::max(),'\n');
        return;
    }

    cin.ignore();
    string msg;
    cout << YELLOW << "  Optional message (press Enter to skip): " << RESET;
    getline(cin, msg);
    msg = sanitize(msg);
    if (msg.size() > 200) msg = msg.substr(0, 200); // cap message length

    Donation nd;
    nd.donationID = ++globalDonations;
    nd.charityID  = charID;
    nd.amount     = amount;
    nd.d          = getCurrentDateTime();
    nd.message    = msg;

    // [FIX-5] Safe array expansion
    Donation *tmp = new Donation[client.nbDonations + 1];
    for (int i = 0; i < client.nbDonations; i++) tmp[i] = client.donations[i];
    tmp[client.nbDonations] = nd;
    delete[] client.donations;
    client.donations = tmp;
    client.nbDonations++;

    target->currentAmount += amount;
    saveCharities();
    saveDonationsForUser(client);

    cout << GREEN << "\n  ✓ Donation of $" << fixed << setprecision(2) << amount
         << " to '" << target->name << "' recorded!\n" << RESET;
    cout << "  Donation ID: " << nd.donationID << "\n";
}

void viewDonations(Client &client) {
    cout << CYAN << "\n  ╔══════════════════════════════════════╗\n";
    cout <<          "  ║          YOUR DONATION HISTORY        ║\n";
    cout <<          "  ╚══════════════════════════════════════╝\n" << RESET;

    if (client.nbDonations == 0) {
        cout << YELLOW << "  No donations yet.\n" << RESET;
        return;
    }

    for (int i = 0; i < client.nbDonations; i++) {
        Donation &dn = client.donations[i];
        string cname = "Unknown";
        for (int j = 0; j < charityCount; j++)
            if (charities[j].charityID == dn.charityID) { cname = charities[j].name; break; }

        cout << "\n  " << BOLD << "#" << dn.donationID << RESET
             << " | " << CYAN << cname << RESET
             << " | $" << GREEN << fixed << setprecision(2) << dn.amount << RESET
             << " | " << dn.d.Date << " " << dn.d.Time << "\n";
        if (!dn.message.empty())
            cout << "  Message: " << YELLOW << dn.message << RESET << "\n";
    }
}

void cancelDonation(Client &client) {
    viewDonations(client);
    if (client.nbDonations == 0) return;

    int did;
    cout << YELLOW << "\n  Enter Donation ID to cancel: " << RESET;
    if (!(cin >> did)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(),'\n'); return; }

    int idx = -1;
    // [FIX-4] Only search within THIS user's donations — no cross-user access
    for (int i = 0; i < client.nbDonations; i++)
        if (client.donations[i].donationID == did) { idx = i; break; }

    if (idx == -1) { cout << RED << "  ✗ Donation not found!\n" << RESET; return; }

    double refund = client.donations[idx].amount;
    for (int j = 0; j < charityCount; j++)
        if (charities[j].charityID == client.donations[idx].charityID) {
            charities[j].currentAmount -= refund;
            if (charities[j].currentAmount < 0) charities[j].currentAmount = 0;
            break;
        }
    saveCharities();

    Donation *tmp = new Donation[client.nbDonations - 1];
    for (int i = 0, j = 0; i < client.nbDonations; i++)
        if (i != idx) tmp[j++] = client.donations[i];
    delete[] client.donations;
    client.donations = tmp;
    client.nbDonations--;

    saveDonationsForUser(client);
    cout << GREEN << "  ✓ Donation cancelled!\n" << RESET;
}

void modifyDonation(Client &client) {
    viewDonations(client);
    if (client.nbDonations == 0) return;

    int did;
    cout << YELLOW << "\n  Enter Donation ID to modify: " << RESET;
    if (!(cin >> did)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(),'\n'); return; }

    Donation *dn = nullptr;
    // [FIX-4] Only allow access to this user's own donations
    for (int i = 0; i < client.nbDonations; i++)
        if (client.donations[i].donationID == did) { dn = &client.donations[i]; break; }

    if (!dn) { cout << RED << "  ✗ Donation not found!\n" << RESET; return; }

    cout << "\n  [1] Modify Amount\n  [2] Change Target Charity\n  Choice: ";
    int ch; cin >> ch;

    if (ch == 1) {
        double newAmt;
        cout << YELLOW << "  New amount ($): " << RESET;
        if (!(cin >> newAmt) || newAmt <= 0) {
            cout << RED << "  ✗ Invalid amount!\n" << RESET;
            cin.clear(); cin.ignore(numeric_limits<streamsize>::max(),'\n');
            return;
        }
        // Revert old, apply new
        for (int j = 0; j < charityCount; j++)
            if (charities[j].charityID == dn->charityID) {
                charities[j].currentAmount -= dn->amount;
                if (charities[j].currentAmount < 0) charities[j].currentAmount = 0;
                break;
            }
        dn->amount = newAmt;
        for (int j = 0; j < charityCount; j++)
            if (charities[j].charityID == dn->charityID) {
                charities[j].currentAmount += dn->amount; break;
            }

    } else if (ch == 2) {
        // Revert from old charity
        for (int j = 0; j < charityCount; j++)
            if (charities[j].charityID == dn->charityID) {
                charities[j].currentAmount -= dn->amount; break;
            }

        string newName;
        cout << YELLOW << "  Enter new charity name: " << RESET;
        cin >> newName;
        newName = sanitize(newName);

        bool found = false;
        for (int j = 0; j < charityCount; j++) {
            if (charities[j].name == newName && charities[j].status == "Open") {
                dn->charityID = charities[j].charityID;
                charities[j].currentAmount += dn->amount;
                found = true; break;
            }
        }
        if (!found) {
            cout << RED << "  ✗ Charity not found or closed! Reverting.\n" << RESET;
            for (int j = 0; j < charityCount; j++)
                if (charities[j].charityID == dn->charityID) {
                    charities[j].currentAmount += dn->amount; break;
                }
            return;
        }
    }

    saveCharities();
    saveDonationsForUser(client);
    cout << GREEN << "  ✓ Donation updated!\n" << RESET;
}

// ─────────────────────────────────────────────
//  USER MANAGEMENT
// ─────────────────────────────────────────────

Client *users     = nullptr;
int     userCount = 0;
int     userCap   = 0; // [FIX-5] track allocated capacity

// [FIX-5] Safe resize — doubles capacity when needed
void ensureUserCapacity() {
    if (userCount < userCap) return;
    int newCap = (userCap == 0) ? 8 : userCap * 2;
    Client *tmp = new Client[newCap];
    for (int i = 0; i < userCount; i++) {
        tmp[i] = users[i];
        tmp[i].donations = users[i].donations; // shallow copy pointer
        users[i].donations = nullptr;           // avoid double-free
    }
    delete[] users;
    users   = tmp;
    userCap = newCap;
}

void loadUsers() {
    ifstream fin(USERS_FILE);
    if (!fin) return;

    int count = 0;
    string line;
    while (getline(fin, line)) if (!line.empty()) count++;
    fin.clear(); fin.seekg(0);

    delete[] users;
    userCap   = count + 16;
    users     = new Client[userCap];
    userCount = 0;

    while (getline(fin, line)) {
        if (line.empty()) continue;
        Client &u = users[userCount++];
        istringstream ss(line);
        int adminFlag = 0;
        // [FIX-3] File format: userID firstName lastName saltHashedPw email phone isAdmin(0/1)
        // password field contains "salt:hash" — no plaintext ever stored
        ss >> u.userID >> u.firstName >> u.lastName
           >> u.password >> u.email >> u.phone >> adminFlag;
        u.isAdmin     = (adminFlag == 1); // [FIX-3] Explicit flag from file
        u.nbDonations = 0;
        u.donations   = nullptr;
    }
    fin.close();
}

void saveUsers() {
    ofstream fout(USERS_FILE);
    for (int i = 0; i < userCount; i++) {
        Client &u = users[i];
        // [FIX-3] Save isAdmin as explicit integer (0 or 1)
        fout << u.userID    << " "
             << u.firstName << " "
             << u.lastName  << " "
             << u.password  << " " // already "salt:hash"
             << u.email     << " "
             << u.phone     << " "
             << (u.isAdmin ? 1 : 0) << "\n";
    }
    fout.close();
}

int getNextUserID() {
    int maxID = 0;
    for (int i = 0; i < userCount; i++)
        if (users[i].userID > maxID) maxID = users[i].userID;
    return maxID + 1;
}

bool emailExists(const string &email) {
    for (int i = 0; i < userCount; i++)
        if (users[i].email == email) return true;
    return false;
}

Client* registerUser() {
    cout << CYAN << "\n  ╔═══════════════════════════════╗\n";
    cout <<          "  ║       CREATE NEW ACCOUNT       ║\n";
    cout <<          "  ╚═══════════════════════════════╝\n" << RESET;

    // [FIX-5] Check capacity before adding
    ensureUserCapacity();
    Client &u = users[userCount];
    u.nbDonations = 0;
    u.donations   = nullptr;
    u.isAdmin     = false; // [FIX-3] NEVER set from input — always false on register

    cout << YELLOW << "  First Name: " << RESET; cin >> u.firstName;
    u.firstName = sanitize(u.firstName);
    if (u.firstName.empty()) { cout << RED << "  ✗ Invalid name!\n" << RESET; return nullptr; }

    cout << YELLOW << "  Last Name: "  << RESET; cin >> u.lastName;
    u.lastName = sanitize(u.lastName);

    // Email validation
    do {
        cout << YELLOW << "  Email: " << RESET; cin >> u.email;
        if (!isValidEmail(u.email))
            cout << RED << "  ✗ Invalid email format.\n" << RESET;
        else if (emailExists(u.email))
            cout << RED << "  ✗ Email already registered!\n" << RESET;
    } while (!isValidEmail(u.email) || emailExists(u.email));

    // Phone validation
    do {
        cout << YELLOW << "  Phone (XX-XXXXXX): " << RESET; cin >> u.phone;
        if (!isValidPhone(u.phone))
            cout << RED << "  ✗ Invalid phone! Use: 03-123456\n" << RESET;
    } while (!isValidPhone(u.phone));

    // Password validation + hashing
    string rawPw;
    do {
        cout << YELLOW << "  Password (min 8 chars, letters+numbers+special): " << RESET;
        cin >> rawPw;
        if (!isValidPassword(rawPw))
            cout << RED << "  ✗ Weak password! Need letters, digits, AND special chars.\n" << RESET;
    } while (!isValidPassword(rawPw));

    // [FIX-1] Hash with salt — NEVER store plaintext
    cout << CYAN << "  Hashing password securely..." << RESET;
    u.password = makePasswordHash(rawPw);
    rawPw.assign(rawPw.size(), '\0'); // wipe plaintext from memory
    cout << GREEN << " Done!\n" << RESET;

    u.userID = getNextUserID();
    userCount++;
    saveUsers();

    cout << GREEN << "\n  ✓ Account created! Your ID is: " << u.userID << "\n" << RESET;
    return &users[userCount - 1];
}

Client* loginUser() {
    // [FIX-6] Check lockout BEFORE accepting any input
    if (g_locked) {
        time_t now = time(nullptr);
        if (now < g_lockUntil) {
            int remaining = (int)(g_lockUntil - now);
            cout << RED << "\n  ⚠  Account locked! Try again in "
                 << remaining << " seconds.\n" << RESET;
            return nullptr;
        } else {
            // Lockout expired — reset
            g_locked        = false;
            g_loginAttempts = 0;
        }
    }

    if (g_loginAttempts >= MAX_ATTEMPTS) {
        cout << RED << "\n  ⚠  Too many failed attempts! Locked.\n" << RESET;
        return nullptr;
    }

    cout << CYAN << "\n  ╔══════════════════════════╗\n";
    cout <<          "  ║         LOGIN              ║\n";
    cout <<          "  ╚══════════════════════════╝\n" << RESET;

    string email, rawPw;
    cout << YELLOW << "  Email: "    << RESET; cin >> email;
    cout << YELLOW << "  Password: " << RESET; cin >> rawPw;

    // Find user by email
    Client *found = nullptr;
    for (int i = 0; i < userCount; i++)
        if (users[i].email == email) { found = &users[i]; break; }

    // [FIX-1] Verify against stored "salt:hash" — constant-time comparison
    bool authenticated = found && verifyPassword(rawPw, found->password);
    rawPw.assign(rawPw.size(), '\0'); // wipe plaintext from memory immediately

    if (!authenticated) {
        g_loginAttempts++;
        int remaining = MAX_ATTEMPTS - g_loginAttempts;
        // [FIX-7] Generic error — do NOT reveal if email exists
        cout << RED << "  ✗ Invalid credentials!";
        if (remaining > 0)
            cout << " " << remaining << " attempt(s) remaining.";
        cout << "\n" << RESET;

        // [FIX-6] Lockout persists even after logout/re-login attempts
        if (g_loginAttempts >= MAX_ATTEMPTS) {
            g_locked    = true;
            g_lockUntil = time(nullptr) + LOCKOUT_SECONDS;
            cout << RED << "  ⚠  Account locked for " << LOCKOUT_SECONDS
                 << " seconds!\n" << RESET;
        }
        return nullptr;
    }

    // Success
    g_loginAttempts = 0;
    g_locked        = false;
    cout << GREEN << "\n  ✓ Welcome back, " << found->firstName << "!\n" << RESET;
    loadDonationsForUser(*found);
    return found;
}

// ─────────────────────────────────────────────
//  SORTING (Merge Sort by amount then date)
// ─────────────────────────────────────────────

void mergeDonations(Donation *arr, int l, int m, int r) {
    int n1 = m - l + 1, n2 = r - m;
    Donation *L = new Donation[n1], *R = new Donation[n2];
    for (int i = 0; i < n1; i++) L[i] = arr[l + i];
    for (int j = 0; j < n2; j++) R[j] = arr[m + 1 + j];

    int i = 0, j = 0, k = l;
    while (i < n1 && j < n2) {
        bool leftFirst = (L[i].amount < R[j].amount) ||
                         (L[i].amount == R[j].amount && dateLessThan(L[i].d, R[j].d));
        if (leftFirst) arr[k++] = L[i++]; else arr[k++] = R[j++];
    }
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];
    delete[] L; delete[] R;
}

void mergeSort(Donation *arr, int l, int r) {
    if (l < r) {
        int m = l + (r - l) / 2;
        mergeSort(arr, l, m);
        mergeSort(arr, m + 1, r);
        mergeDonations(arr, l, m, r);
    }
}

Donation* getSortedDonations(Client &client, int &count) {
    count = client.nbDonations;
    if (count == 0) return nullptr;
    Donation *sorted = new Donation[count];
    for (int i = 0; i < count; i++) sorted[i] = client.donations[i];
    mergeSort(sorted, 0, count - 1);
    return sorted;
}

// ─────────────────────────────────────────────
//  PDF REPORT GENERATION
// ─────────────────────────────────────────────

void generatePDFReport(Client &client) {
    int count;
    Donation *sorted = getSortedDonations(client, count);

    string fname = DATA_DIR + "report_" + to_string(client.userID) + ".html";
    ofstream fout(fname);

    fout << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Donation Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Source+Sans+3:wght@300;400;600&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Source Sans 3', sans-serif; background: #f8f7f4; color: #1a1a2e; }
  .page { max-width: 850px; margin: 0 auto; background: white; min-height: 100vh; padding: 60px; box-shadow: 0 0 40px rgba(0,0,0,0.1); }
  .header { border-bottom: 3px solid #16213e; padding-bottom: 30px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: flex-end; }
  .logo { font-family: 'Playfair Display', serif; font-size: 2.4rem; color: #16213e; }
  .logo span { color: #e94560; }
  .date { font-size: 0.85rem; color: #666; text-align: right; }
  .section-title { font-family: 'Playfair Display', serif; font-size: 1.1rem; text-transform: uppercase; letter-spacing: 0.2em; color: #e94560; margin-bottom: 20px; }
  .donor-card { background: linear-gradient(135deg, #16213e, #0f3460); color: white; border-radius: 16px; padding: 30px; margin-bottom: 40px; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .donor-card h2 { font-family: 'Playfair Display', serif; font-size: 1.8rem; grid-column: 1/-1; margin-bottom: 8px; }
  .info-item label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.15em; opacity: 0.6; display: block; }
  .info-item span { font-size: 1rem; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
  thead tr { background: #16213e; color: white; }
  thead th { padding: 14px 18px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 600; }
  tbody tr:nth-child(even) { background: #f8f7f4; }
  tbody td { padding: 14px 18px; border-bottom: 1px solid #eee; font-size: 0.95rem; }
  .amount { font-weight: 700; color: #0f3460; font-size: 1.05rem; }
  .total-row { background: linear-gradient(90deg, #16213e, #0f3460) !important; color: white; }
  .total-row td { font-weight: 700; font-size: 1rem; padding: 18px; }
  .footer { border-top: 1px solid #eee; padding-top: 20px; font-size: 0.8rem; color: #999; text-align: center; }
  @media print { .page { box-shadow: none; } }
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div class="logo">Charity<span>Hub</span></div>
    <div class="date">)" << escapeHtml(getCurrentDateTime().Date) << " at " << escapeHtml(getCurrentDateTime().Time) << R"(</div>
  </div>
  <div class="section-title">Donor Profile</div>
  <div class="donor-card">
    <h2>)" << escapeHtml(client.firstName) << " " << escapeHtml(client.lastName) << R"(</h2>
    <div class="info-item"><label>Email</label><span>)" << escapeHtml(client.email) << R"(</span></div>
    <div class="info-item"><label>Phone</label><span>)" << escapeHtml(client.phone) << R"(</span></div>
    <div class="info-item"><label>Donor ID</label><span>#)" << client.userID << R"(</span></div>
    <div class="info-item"><label>Total Donations</label><span>)" << count << R"(</span></div>
  </div>
  <div class="section-title">Donation History (Sorted by Amount &amp; Date)</div>
  <table>
    <thead>
      <tr><th>#</th><th>ID</th><th>Charity</th><th>Amount</th><th>Date</th><th>Time</th><th>Message</th></tr>
    </thead>
    <tbody>)";

    double total = 0;
    for (int i = 0; i < count; i++) {
        Donation &dn = sorted[i];
        string cname = "Unknown";
        for (int j = 0; j < charityCount; j++)
            if (charities[j].charityID == dn.charityID) { cname = charities[j].name; break; }
        total += dn.amount;
        fout << "\n      <tr>"
             << "<td>" << (i+1) << "</td>"
             << "<td>" << dn.donationID << "</td>"
             << "<td>" << escapeHtml(cname) << "</td>"
             << "<td class='amount'>$" << fixed << setprecision(2) << dn.amount << "</td>"
             << "<td>" << escapeHtml(dn.d.Date) << "</td>"
             << "<td>" << escapeHtml(dn.d.Time) << "</td>"
             << "<td>" << (dn.message.empty() ? "—" : escapeHtml(dn.message)) << "</td>"
             << "</tr>";
    }

    fout << R"(
      <tr class="total-row">
        <td colspan="3">TOTAL DONATED</td>
        <td>$)" << fixed << setprecision(2) << total << R"(</td>
        <td colspan="3"></td>
      </tr>
    </tbody>
  </table>
  <div class="footer">
    <p>Report generated by CharityHub Donation Management System.</p>
    <p>)" << escapeHtml(getCurrentDateTime().Date) << " at " << escapeHtml(getCurrentDateTime().Time) << R"(</p>
  </div>
</div>
</body>
</html>)";

    fout.close();
    delete[] sorted;
    cout << GREEN << "\n  ✓ Report saved: " << fname << "\n" << RESET;
    cout << CYAN  << "  → Open in browser and Ctrl+P to save as PDF!\n" << RESET;
}

// ─────────────────────────────────────────────
//  JSON DATABASE (Bonus)
// ─────────────────────────────────────────────

void saveToJSON() {
    ofstream f(JSON_FILE);
    f << "{\n";

    // Users — [FIX-2] NEVER write plaintext password, only "salt:hash"
    f << "  \"users\": [\n";
    for (int i = 0; i < userCount; i++) {
        Client &u = users[i];
        f << "    {\n"
          << "      \"id\": "          << u.userID    << ",\n"
          << "      \"firstName\": \"" << escapeHtml(u.firstName) << "\",\n"
          << "      \"lastName\": \""  << escapeHtml(u.lastName)  << "\",\n"
          << "      \"email\": \""     << escapeHtml(u.email)     << "\",\n"
          << "      \"phone\": \""     << escapeHtml(u.phone)     << "\",\n"
          // [FIX-2] password stored as opaque "salt:hash" token only
          << "      \"passwordHash\": \"" << u.password << "\",\n"
          << "      \"isAdmin\": "    << (u.isAdmin ? "true" : "false") << "\n"
          << "    }" << (i < userCount - 1 ? "," : "") << "\n";
    }
    f << "  ],\n";

    // Charities
    f << "  \"charities\": [\n";
    for (int i = 0; i < charityCount; i++) {
        Charity &c = charities[i];
        f << "    {\n"
          << "      \"id\": " << c.charityID << ",\n"
          << "      \"name\": \"" << escapeHtml(c.name) << "\",\n"
          << "      \"description\": \"" << escapeHtml(c.description) << "\",\n"
          << "      \"targetAmount\": " << fixed << setprecision(2) << c.targetAmount << ",\n"
          << "      \"currentAmount\": " << c.currentAmount << ",\n"
          << "      \"deadline\": \"" << c.deadline.Date << " " << c.deadline.Time << "\",\n"
          << "      \"status\": \"" << c.status << "\"\n"
          << "    }" << (i < charityCount - 1 ? "," : "") << "\n";
    }
    f << "  ]\n}\n";
    f.close();
    cout << GREEN << "  ✓ JSON database updated: " << JSON_FILE << "\n" << RESET;
}

// ─────────────────────────────────────────────
//  WEB DASHBOARD GENERATOR
//  [FIX-7] Only shows public stats — no internal user data, no passwords
// ─────────────────────────────────────────────

void generateWebDashboard() {
    ofstream f(WEB_DASHBOARD);

    // Only public, non-sensitive stats
    double totalRaised = 0;
    int    openCount   = 0;
    for (int i = 0; i < charityCount; i++) {
        totalRaised += charities[i].currentAmount;
        if (charities[i].status == "Open") openCount++;
    }

    f << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
      << "<meta charset=\"UTF-8\">\n"
      << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">\n"
      << "<title>CharityHub Dashboard</title>\n"
      << "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n"
      << "<link href=\"https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Sans:wght@300;400;500&display=swap\" rel=\"stylesheet\">\n"
      << "<style>\n"
      << "  :root { --ink:#0d0d1a; --cream:#f5f0e8; --gold:#c9a84c; --rose:#e94560; --teal:#0f7ea5; --border:rgba(0,0,0,0.08); --shadow:0 4px 24px rgba(13,13,26,0.08); }\n"
      << "  * { margin:0; padding:0; box-sizing:border-box; }\n"
      << "  body { font-family:'DM Sans',sans-serif; background:var(--cream); color:var(--ink); }\n"
      << "  nav { position:fixed; top:0; left:0; right:0; z-index:100; display:flex; align-items:center; justify-content:space-between; padding:0 40px; height:64px; background:rgba(245,240,232,0.85); backdrop-filter:blur(12px); border-bottom:1px solid var(--border); }\n"
      << "  .nav-brand { font-family:'Syne',sans-serif; font-size:1.4rem; font-weight:800; color:var(--ink); }\n"
      << "  .nav-brand span { color:var(--rose); }\n"
      << "  .hero { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:100px 40px 60px; text-align:center; background:radial-gradient(ellipse 80% 60% at 50% 0%,rgba(201,168,76,0.12) 0%,transparent 60%),var(--cream); }\n"
      << "  .hero h1 { font-family:'Syne',sans-serif; font-size:clamp(3rem,8vw,6rem); font-weight:800; line-height:1; margin-bottom:24px; }\n"
      << "  .hero h1 .accent { color:var(--rose); display:block; }\n"
      << "  .hero p { font-size:1.15rem; max-width:520px; margin:0 auto 40px; opacity:0.65; line-height:1.7; }\n"
      << "  .stats { display:grid; grid-template-columns:repeat(3,1fr); gap:1px; background:var(--border); margin:0 40px; border-radius:16px; overflow:hidden; box-shadow:var(--shadow); }\n"
      << "  .stat { background:white; padding:40px; text-align:center; }\n"
      << "  .stat-num { font-family:'Syne',sans-serif; font-size:2.5rem; font-weight:800; color:var(--ink); }\n"
      << "  .stat-num span { color:var(--rose); }\n"
      << "  .stat-label { font-size:0.85rem; opacity:0.55; margin-top:6px; text-transform:uppercase; letter-spacing:0.1em; }\n"
      << "  section { padding:80px 40px; max-width:1200px; margin:0 auto; }\n"
      << "  .charity-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:24px; }\n"
      << "  .charity-card { background:white; border-radius:20px; overflow:hidden; border:1px solid var(--border); transition:all 0.3s; box-shadow:var(--shadow); }\n"
      << "  .charity-card:hover { transform:translateY(-4px); box-shadow:0 20px 48px rgba(13,13,26,0.12); }\n"
      << "  .card-img { height:140px; background:linear-gradient(135deg,var(--ink),#1a1a3e); display:flex; align-items:center; justify-content:center; position:relative; }\n"
      << "  .card-icon { font-size:3.5rem; opacity:0.3; }\n"
      << "  .card-status { position:absolute; top:12px; right:12px; padding:3px 10px; border-radius:20px; font-size:0.72rem; font-weight:700; text-transform:uppercase; }\n"
      << "  .status-open { background:rgba(39,174,96,0.9); color:white; }\n"
      << "  .status-closed { background:rgba(231,76,60,0.9); color:white; }\n"
      << "  .card-body { padding:22px; }\n"
      << "  .card-name { font-family:'Syne',sans-serif; font-size:1.2rem; font-weight:700; margin-bottom:6px; }\n"
      << "  .card-desc { font-size:0.85rem; opacity:0.6; line-height:1.6; margin-bottom:16px; }\n"
      << "  .progress-label { display:flex; justify-content:space-between; font-size:0.8rem; margin-bottom:6px; font-weight:500; }\n"
      << "  .progress-bar { height:6px; background:#f0f0f0; border-radius:10px; overflow:hidden; margin-bottom:16px; }\n"
      << "  .progress-fill { height:100%; border-radius:10px; background:linear-gradient(90deg,var(--teal),var(--gold)); }\n"
      << "  .card-footer { display:flex; justify-content:space-between; align-items:center; }\n"
      << "  .card-amount { font-family:'Syne',sans-serif; font-size:1rem; font-weight:700; }\n"
      << "  .card-deadline { font-size:0.75rem; opacity:0.5; }\n"
      << "  footer { background:var(--ink); color:white; padding:40px; text-align:center; }\n"
      << "  .footer-brand { font-family:'Syne',sans-serif; font-size:1.4rem; font-weight:800; margin-bottom:8px; }\n"
      << "  .footer-brand span { color:var(--rose); }\n"
      << "</style>\n</head>\n<body>\n";

    // NAV
    f << "<nav><div class=\"nav-brand\">Charity<span>Hub</span></div>"
      << "<span style=\"font-size:0.85rem;opacity:0.5;\">Live Dashboard</span></nav>\n";

    // HERO
    f << "<div class=\"hero\"><div>\n"
      << "  <h1>Give with <span class=\"accent\">Purpose.</span></h1>\n"
      << "  <p>Transparent charity management. Every donation tracked and verified.</p>\n"
      << "</div></div>\n";

    // STATS — [FIX-7] Only show aggregated public numbers, no user data
    f << "<div class=\"stats\">\n"
      << "  <div class=\"stat\"><div class=\"stat-num\">" << charityCount << "<span>+</span></div><div class=\"stat-label\">Total Charities</div></div>\n"
      << "  <div class=\"stat\"><div class=\"stat-num\">$" << fixed << setprecision(0) << totalRaised << "</div><div class=\"stat-label\">Total Raised</div></div>\n"
      << "  <div class=\"stat\"><div class=\"stat-num\">" << openCount << "</div><div class=\"stat-label\">Open Campaigns</div></div>\n"
      << "</div>\n";

    // CHARITIES
    f << "<section>\n<h2 style=\"font-family:'Syne',sans-serif;font-size:2rem;font-weight:800;margin-bottom:32px;\">Active Campaigns</h2>\n"
      << "<div class=\"charity-grid\">\n";

    string icons[] = {"&#127757;","&#10084;","&#127807;","&#127891;","&#127973;","&#129309;","&#128154;","&#127754;"};
    for (int i = 0; i < charityCount; i++) {
        Charity &c = charities[i];
        double pct = (c.targetAmount > 0) ? min(100.0, c.currentAmount / c.targetAmount * 100.0) : 0;
        string statusClass = (c.status == "Open") ? "status-open" : "status-closed";
        // [FIX-7] escapeHtml on all charity data written to web output
        f << "  <div class=\"charity-card\">\n"
          << "    <div class=\"card-img\"><div class=\"card-icon\">" << icons[i % 8] << "</div>"
          << "<div class=\"card-status " << statusClass << "\">" << escapeHtml(c.status) << "</div></div>\n"
          << "    <div class=\"card-body\">\n"
          << "      <div class=\"card-name\">" << escapeHtml(c.name) << "</div>\n"
          << "      <div class=\"card-desc\">" << escapeHtml(c.description) << "</div>\n"
          << "      <div class=\"progress-label\"><span>$" << fixed << setprecision(0) << c.currentAmount << " raised</span>"
          << "<span>" << fixed << setprecision(1) << pct << "%</span></div>\n"
          << "      <div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width:" << pct << "%;\"></div></div>\n"
          << "      <div class=\"card-footer\">"
          << "<div><div class=\"card-amount\">Goal: $" << fixed << setprecision(0) << c.targetAmount << "</div>"
          << "<div class=\"card-deadline\">Deadline: " << escapeHtml(c.deadline.Date) << "</div></div>"
          << "</div>\n"
          << "    </div>\n"
          << "  </div>\n";
    }
    f << "</div>\n</section>\n";

    // FOOTER
    f << "<footer>\n"
      << "  <div class=\"footer-brand\">Charity<span>Hub</span></div>\n"
      << "  <p style=\"opacity:0.4;font-size:0.85rem;\">Programming II Project — University Antonine</p>\n"
      << "  <p style=\"opacity:0.3;font-size:0.75rem;margin-top:8px;\">Generated: "
      << escapeHtml(getCurrentDateTime().Date) << " " << escapeHtml(getCurrentDateTime().Time) << "</p>\n"
      << "</footer>\n"
      << "</body>\n</html>\n";

    f.close();
    cout << GREEN << "  ✓ Web dashboard generated: " << WEB_DASHBOARD << "\n" << RESET;
}

// ─────────────────────────────────────────────
//  UI HELPERS
// ─────────────────────────────────────────────

void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    cout << "\033[2J\033[1;1H";
#endif
}

void printBanner() {
    clearScreen();
    cout << BLUE << BOLD
         << "\n  ╔══════════════════════════════════════════════════════╗\n"
         << "  ║                                                      ║\n"
         << "  ║        ♥  C H A R I T Y H U B  ♥                   ║\n"
         << "  ║      Donation Management System v2.0 [SECURE]        ║\n"
         << "  ║                                                      ║\n"
         << "  ╚══════════════════════════════════════════════════════╝\n"
         << RESET;
}

void pauseInput() {
    cout << "\n  " << YELLOW << "Press Enter to continue..." << RESET;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    cin.get();
}

// ─────────────────────────────────────────────
//  ADMIN MENU
// ─────────────────────────────────────────────

void adminMenu(Client &admin) {
    int choice;
    do {
        printBanner();
        cout << RED << BOLD << "\n  ┌──────────────────────────────────┐\n";
        cout <<                 "  │       ADMIN CONTROL PANEL         │\n";
        cout <<                 "  └──────────────────────────────────┘\n" << RESET;
        cout << "  Welcome, " << BOLD << admin.firstName << RESET << "\n\n";
        cout << "  [1] Add Charity Campaign\n";
        cout << "  [2] Remove Charity\n";
        cout << "  [3] Modify Charity\n";
        cout << "  [4] Browse All Charities\n";
        cout << "  [5] Refresh Web Dashboard\n";
        cout << "  [6] Export JSON Database\n";
        cout << "  [0] Logout\n";
        cout << "\n  " << YELLOW << "Choice: " << RESET;
        cin >> choice;

        switch (choice) {
            case 1: addCharity();          pauseInput(); break;
            case 2: removeCharity();       pauseInput(); break;
            case 3: modifyCharity();       pauseInput(); break;
            case 4: browseCharities();     pauseInput(); break;
            case 5: generateWebDashboard();pauseInput(); break;
            case 6: saveToJSON();          pauseInput(); break;
            case 0: cout << CYAN << "\n  Goodbye, " << admin.firstName << "!\n" << RESET; break;
            default: cout << RED << "  Invalid choice!\n" << RESET;
        }
    } while (choice != 0);
}

// ─────────────────────────────────────────────
//  DONOR MENU
// ─────────────────────────────────────────────

void donorMenu(Client &donor) {
    int choice;
    do {
        printBanner();
        cout << GREEN << BOLD << "\n  ┌──────────────────────────────────┐\n";
        cout <<                  "  │         DONOR DASHBOARD            │\n";
        cout <<                  "  └──────────────────────────────────┘\n" << RESET;
        cout << "  Welcome, " << BOLD << donor.firstName << " " << donor.lastName << RESET
             << "  |  Donations: " << CYAN << donor.nbDonations << RESET << "\n\n";
        cout << "  [1] Browse Available Charities\n";
        cout << "  [2] Make a Donation\n";
        cout << "  [3] View My Donations\n";
        cout << "  [4] Cancel a Donation\n";
        cout << "  [5] Modify a Donation\n";
        cout << "  [6] Download Donation Report (PDF)\n";
        cout << "  [7] View Web Dashboard\n";
        cout << "  [0] Logout\n";
        cout << "\n  " << YELLOW << "Choice: " << RESET;
        cin >> choice;

        switch (choice) {
            case 1: browseCharities();        pauseInput(); break;
            case 2: makeDonation(donor);      pauseInput(); break;
            case 3: viewDonations(donor);     pauseInput(); break;
            case 4: cancelDonation(donor);    pauseInput(); break;
            case 5: modifyDonation(donor);    pauseInput(); break;
            case 6: generatePDFReport(donor); pauseInput(); break;
            case 7: generateWebDashboard();
                    cout << CYAN << "  Open 'dashboard.html' in your browser!\n" << RESET;
                    pauseInput(); break;
            case 0: generatePDFReport(donor); // auto-generate on exit
                    cout << CYAN << "\n  Goodbye, " << donor.firstName << "!\n" << RESET; break;
            default: cout << RED << "  Invalid choice!\n" << RESET;
        }
    } while (choice != 0);
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────

int main() {
    loadCharities();
    loadUsers();
    generateWebDashboard();

    bool running = true;
    while (running) {
        printBanner();
        cout << "\n  " << BOLD << "Do you have an account?" << RESET << "\n\n";
        cout << "  [1] Login\n";
        cout << "  [2] Register (New User)\n";
        cout << "  [0] Exit\n";
        cout << "\n  " << YELLOW << "Choice: " << RESET;

        int choice;
        cin >> choice;
        Client *currentUser = nullptr;

        if (choice == 1) {
            currentUser = loginUser();
            if (!currentUser) {
                // [FIX-6] Don't reset lockout on failed login — already handled inside loginUser()
                pauseInput();
                continue;
            }
        } else if (choice == 2) {
            currentUser = registerUser();
            if (!currentUser) { pauseInput(); continue; }
            loadDonationsForUser(*currentUser);
        } else if (choice == 0) {
            running = false; break;
        } else {
            cout << RED << "  Invalid choice!\n" << RESET;
            pauseInput(); continue;
        }

        if (currentUser->isAdmin) adminMenu(*currentUser);
        else donorMenu(*currentUser);

        // Save on logout
        saveUsers();
        saveToJSON();
        generateWebDashboard();
        // [FIX-6] Do NOT reset g_loginAttempts or g_locked here — survives logout
    }

    // Cleanup
    delete[] charities;
    for (int i = 0; i < userCount; i++)
        delete[] users[i].donations;
    delete[] users;

    cout << CYAN << "\n  Thank you for using CharityHub!\n\n" << RESET;
    return 0;
}
