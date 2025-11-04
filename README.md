# 🔐 Secure Password Manager (CLI-Based)

A command-line password manager built with **Go**, providing **strong encryption**, **secure memory handling**, and **comprehensive protection** for your sensitive data.

Your passwords are safeguarded using **AES-256-GCM encryption** and **scrypt key derivation** — cryptographic standards trusted by governments and financial institutions.

-----

## 🧠 Important Note

All testing was performed on **Windows 11 Command Prompt**.

-----

## 🛡️ Security Highlights

  * **AES-256-GCM Encryption**: Military-grade encryption protects your passwords.
  * **Scrypt Key Derivation**: Memory-hard algorithm makes brute-force attacks impractical.
  * **Secure Memory Management**: Multi-pass wiping and memory locking prevent data recovery.
  * **Auto-Lock Sessions**: **2-minute inactivity timeout** automatically secures your vault.
  * **Open Source**: Fully auditable code – trust through transparency.

-----

## ⚙️ Required Software

  * **Go Programming Language** (version 1.21 or later)

### Installation of Go

1.  Visit [https://go.dev/dl/](https://go.dev/dl/)
2.  Download the installer for your OS:
      * Windows: `go1.21.x.windows-amd64.msi`
3.  Verify installation:

<!-- end list -->

```bash
go version
```

Expected output:

```
go version go1.21.x windows/amd64
```

-----

## 🧩 Installation Guide

### Step 1: Download the Source Code

**Option A: Using Git**

```bash
git clone https://github.com/mmw08/Wehbe_Password_Manager.git
cd Wehbe_Password_Manager
```

**Option B: Manual Download**

1. Download the source code (the .go file provided)


2. Create a folder: mkdir password-manager

```bash
# Create a folder
mkdir password-manager
# Save provided code as main.go in this folder
```
3. Save the code as main.go in this folder.
4. Open **Command Prompt** in this folder.
5. run the below commend
```bash
#get the mod of GO in the directary you choose
go mod init password-manager 
```

### Step 2: Install Required Dependencies

Run the following commands:

```bash

# Clipboard library (for copy/paste functionality)
go get github.com/atotto/clipboard

# Cryptography library (for scrypt key derivation)
go get golang.org/x/crypto/scrypt

# Terminal library (for secure password input)
go get golang.org/x/term
```

### Step 3: Build the Application

Windows:

```bash
go build -o wehbe-password-manager.exe main.go
```

### Step 4: Run and Verify

Run the application:

```bash
wehbe-password-manager.exe
```

You should see:

```
📝 No database found. Let's create a new one!

Master Password Requirements:
 • At least 12 characters
 • One uppercase letter (A-Z)
 • One lowercase letter (a-z)
 • One digit (0-9)
 • One special character (!@#$%^&*...)
```

Create your Master Password, confirm it, and view password strength feedback:

```
💚 Password Strength: VERY STRONG
✅ Database created successfully!
```

-----

## 🧭 Application Usage

Once unlocked, you’ll see:

```
⏱️  Auto-lock in: 1m 59s

📋 MAIN MENU
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. 📝 Add New Password
2. 🔍 Retrieve Password
3. ✏️  Update Password
4. 🗑️  Delete Password
5. 📜 List All Passwords
6. 🎲 Generate Random Password
7. 🔍 Security Audit
8. ☁️  Cloud Sync Setup
9. 🔑 Change Master Password
10. 🔒 Lock & Exit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Select option (1-10):
```

### Menu Features

| Option | Description |
| :--- | :--- |
| **1** | Add a new password (website, username, password, notes). The system can generate a random password. |
| **2** | Retrieve a password by website name — choose to copy to clipboard (10 sec) or display on screen (10 sec). |
| **3** | Update the password, username, or notes for an existing entry. |
| **4** | Delete a saved password entry. |
| **5** | List all stored website names and corresponding usernames. |
| **6** | Generate a strong random password. |
| **7** | Run a **Security Audit** to detect weak or duplicate passwords. |
| **8** | Setup cloud sync (optional) to save an encrypted backup file to OneDrive. |
| **9** | Change the master password (re-encrypts the entire database). |
| **10** | Lock and exit — securely clears memory. |

# ⚠️ **Important:**
>
> If the master password is forgotten, all stored data is lost permanently.

-----

## ☁️ Recover the file if lost

### Setup cloud sync on Device

1.  Enable cloud sync (**option 8**).
2.  Configure the cloud folder path (e.g., OneDrive).
3.  Lock and exit — this triggers the first sync.

### Setup if file is lost 

1.  Install the password manager.
2.  Download `passwords.db` file.
3.  Copy `passwords.db` to your local folder where password manager is exist.
4.  Run the application and unlock it.

-----

## 🔒 Security Best Practices

### Every 6 Months:

  * Change passwords for **critical accounts** (email, banking, etc.)
  * Consider changing your **master password**
  * Delete unused accounts
  * Run a **Security Audit** (**option 7**)
      * Check for weak passwords
      * Check for duplicates



-----

## 🏁 Conclusion

You now have a secure, open-source, and fully transparent password manager that empowers you to take control of your credentials.

### 🧭 Golden Rules

1.  **🔑 Strong Master Password**: Single point of security — protect it well.
2.  **💾 Regular Backups**: Guard against data loss.
3.  **🔍 Monthly Audits**: Maintain password health.
4.  **🔒 Lock When Away**: Auto-timeout helps, but stay cautious.

**Stay Secure. Stay Private. Stay in Control.**
