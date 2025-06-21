# Secure Password Manager with GUI and Encryption

This is a desktop **Password Manager** application built with **Python** using the **Tkinter GUI library**. It helps users securely store and manage their login credentials, generate strong passwords, and protect access with an **admin authentication system**.

All saved passwords are **encrypted using Fernet (AES-based symmetric encryption)** and stored in a JSON file. The application also provides features like password visibility toggle, search, and entry viewing.

---

## 🔧 Required Libraries

To run this project, make sure you have the following Python libraries installed:

- `tkinter` (comes with Python)
- `cryptography`
- `pyperclip`
- `json` (built-in)
- `os` (built-in)
- `random` (built-in)

### Install the external libraries:

```bash
pip install cryptography pyperclip

## Features

- Admin login required to use the app
- Fernet encryption to securely store passwords
- GUI interface built using Tkinter
- Add new credentials (website, email, password)
- Password generator (auto-copies to clipboard)
- Search saved credentials by website name
- View all saved entries
- Toggle password visibility
- Change admin password from within the app

---

## Technologies Used

- Python 3
- Tkinter (GUI)
- Cryptography (Fernet encryption)
- JSON (for data storage)
- Pyperclip (for clipboard copy)

---

## How to Run the Program

### 1. Install Python

Make sure Python 3 is installed. You can download it from: https://www.python.org/downloads/

### 2. Install Required Libraries

Open command prompt or terminal and run:

pip install cryptography pyperclip

