from tkinter import *
from tkinter import messagebox, simpledialog
import random as rd
import pyperclip
import json
import os
from cryptography.fernet import Fernet

# ---------------------------- CONSTANTS ------------------------------- #
FONT = ("Arial", 10)
BG_COLOR = "#b8c9cb"
BUTTON_COLOR = "#bc4a4a"
TEXT_COLOR = "#000000"
ENTRY_BG = "#ffffff"

letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

# ---------------------------- ENCRYPTION SETUP ------------------------------- #
# Generate or load encryption key
KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

SECRET_KEY = load_or_create_key()
fernet = Fernet(SECRET_KEY)

def encrypt_password(password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

# ---------------------------- ADMIN SETUP ------------------------------- #
ADMIN_FILE = "admin_pass.json"

def get_admin_password():
    if os.path.exists(ADMIN_FILE):
        try:
            with open(ADMIN_FILE, "r") as f:
                data = json.load(f)
                return data.get("password", "")
        except:
            return ""
    return ""

def set_admin_password(pwd):
    with open(ADMIN_FILE, "w") as f:
        json.dump({"password": encrypt_password(pwd)}, f)

def prompt_set_password():
    while True:
        pwd = simpledialog.askstring("Set Admin Password", "Enter a new admin password:", show='*')
        confirm = simpledialog.askstring("Confirm Password", "Re-enter the admin password:", show='*')
        if not pwd or not confirm:
            messagebox.showerror("Cancelled", "Admin password is required to use the app.")
            exit()
        if pwd == confirm:
            set_admin_password(pwd)
            messagebox.showinfo("Success", "Admin password set successfully.")
            break
        else:
            messagebox.showerror("Mismatch", "Passwords did not match. Try again.")

def prompt_verify_password():
    stored = get_admin_password()
    if not stored:
        prompt_set_password()
    else:
        try:
            pwd = simpledialog.askstring("Admin Login", "Enter admin password to continue:", show='*')
            if decrypt_password(stored) != pwd:
                messagebox.showerror("Access Denied", "Wrong admin password. Exiting...")
                exit()
        except:
            messagebox.showerror("Error", "Admin password error.")
            exit()

def change_admin_password():
    old = simpledialog.askstring("Change Admin Password", "Enter current password:", show='*')
    if not old:
        return
    if decrypt_password(get_admin_password()) != old:
        messagebox.showerror("Error", "Incorrect current password.")
        return
    prompt_set_password()

# Prompt admin before launching app
prompt_verify_password()

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def gen_pass():
    while True:
        password = [
            rd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),  # at least one uppercase
            rd.choice("abcdefghijklmnopqrstuvwxyz"),  # at least one lowercase
            rd.choice(numbers),                       # at least one digit
            rd.choice(symbols)                        # at least one symbol
        ]

        remaining_length = rd.randint(3, 6)
        all_chars = letters + numbers + symbols
        password += [rd.choice(all_chars) for _ in range(remaining_length)]
        rd.shuffle(password)
        rdpassw = "".join(password)

        if len(rdpassw) >= 7:
            pass_entry.delete(0, END)
            pass_entry.insert(0, rdpassw)
            pyperclip.copy(rdpassw)
            break

# ---------------------------- SAVE PASSWORD ------------------------------- #
def add():
    web = web_entry.get().strip().title()
    uname = name_entry.get().strip()
    passw = pass_entry.get().strip()

    if not web or not uname or not passw:
        messagebox.showwarning(title="Blanks", message="Please don't leave any field blank.")
        return

    # Password strength check
    if (len(passw) < 7 or
        not any(char.isupper() for char in passw) or
        not any(char.isdigit() for char in passw) or
        not any(char in symbols for char in passw)):
        messagebox.showerror(
            title="Weak Password",
            message="Password must be at least 7 characters long and include:\n• At least one uppercase letter\n• At least one number\n• At least one symbol (!#$%&()*+)"
        )
        return

    sure = messagebox.askyesno(
        title=web,
        message=(f"Are You Sure?\nEmail/Username: {uname}\nPassword: {passw}")
    )

    if sure:
        # Encrypt the password before saving
        encrypted_pass = encrypt_password(passw)
        
        new_item = {
            web: {
                "Email": uname,
                "Password": encrypted_pass  # Store encrypted password
            }
        }

        web_entry.delete(0, END)
        name_entry.delete(0, END)
        pass_entry.delete(0, END)
        web_entry.focus()

        try:
            with open("data.json", "r") as file:
                data = json.load(file)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            with open("data.json", "w") as dt:
                json.dump(new_item, dt, indent=4)
        else:
            data.update(new_item)
            with open("data.json", "w") as dt:
                json.dump(data, dt, indent=4)

# ---------------------------- SEARCH PASSWORD ------------------------------- #
def search_pass():
    search_bu.config(bg="#2a5ba5")
    web = web_entry.get().strip().title()
    try:
        with open("data.json") as saved:
            data = json.load(saved)
    except FileNotFoundError:
        messagebox.showinfo(title=web, message="There are no saved passwords.")
    except json.decoder.JSONDecodeError:
        messagebox.showinfo(title=web, message="The data file is empty.")
    else:
        if web in data:
            username = data[web]["Email"]
            encrypted_password = data[web]["Password"]
            # Decrypt the password for display
            try:
                decrypted_password = decrypt_password(encrypted_password)
                messagebox.showinfo(title=web, message=f"Email/Username: {username}\nPassword: {decrypted_password}")
            except:
                messagebox.showerror("Error", "Failed to decrypt password.")
        else:
            messagebox.showinfo(title=web, message=f"There is no data associated with {web}.")
    finally:
        window.after(500, lambda: search_bu.config(bg=BUTTON_COLOR))

# ---------------------------- VIEW ALL ENTRIES ------------------------------- #
def view_all():
    try:
        with open("data.json") as file:
            data = json.load(file)
    except FileNotFoundError:
        messagebox.showinfo(title="Oops!", message="No saved passwords found.")
        return
    except json.decoder.JSONDecodeError:
        messagebox.showinfo(title="Oops!", message="The data file is empty.")
        return

    all_window = Toplevel(window)
    all_window.title("All Saved Entries")
    all_window.config(padx=20, pady=20, bg=BG_COLOR)
    all_window.geometry("+%d+%d" % (window.winfo_x()+50, window.winfo_y()+50))

    scrollbar = Scrollbar(all_window)
    scrollbar.pack(side=RIGHT, fill=Y)

    listbox = Listbox(all_window, width=60, height=15, yscrollcommand=scrollbar.set,
                     bg=ENTRY_BG, fg=TEXT_COLOR, font=FONT)
    
    for website, details in data.items():
        # Decrypt the password for display
        try:
            decrypted_password = decrypt_password(details["Password"])
            listbox.insert(END, f"Website: {website}")
            listbox.insert(END, f"  Username: {details['Email']}")
            listbox.insert(END, f"  Password: {decrypted_password}")
            listbox.insert(END, "-"*50)
        except:
            listbox.insert(END, f"Website: {website} [Error decrypting password]")
            listbox.insert(END, "-"*50)
    
    listbox.pack(side=LEFT, fill=BOTH)
    scrollbar.config(command=listbox.yview)

# ---------------------------- TOGGLE PASSWORD VISIBILITY ------------------------------- #
def toggle_password():
    if pass_entry.cget('show') == "":
        pass_entry.config(show="*")
        show_pass_check.config(text="Show Password")
    else:
        pass_entry.config(show="")
        show_pass_check.config(text="Hide Password")

# ---------------------------- UI SETUP ------------------------------- #
window = Tk()
window.title("Password Manager")
window.config(bg=BG_COLOR)

# Center the window on screen
window.update_idletasks()
width = window.winfo_width()
height = window.winfo_height()
x = (window.winfo_screenwidth() // 2) - (width // 2)
y = (window.winfo_screenheight() // 2) - (height // 2)
window.geometry(f'500x500+{x}+{y}')

# Main frame for centering content
main_frame = Frame(window, bg=BG_COLOR, padx=20, pady=20)
main_frame.pack(expand=True)

# Logo
canvas = Canvas(main_frame, bg=BG_COLOR, highlightthickness=0)
img = PhotoImage(file="logo.png").subsample(2, 2)  # Scale down if needed
canvas.create_image(0, 0, image=img, anchor = "nw")
canvas.config(width=img.width(), height=img.height()) 
canvas.grid(row=0, column=1, pady=(10, 20))

# Labels
web_text = Label(main_frame, text="Website:", font=FONT, bg=BG_COLOR, fg=TEXT_COLOR)
web_text.grid(row=1, column=0, sticky="e", pady=5)

name_text = Label(main_frame, text="Email/Username:", font=FONT, bg=BG_COLOR, fg=TEXT_COLOR)
name_text.grid(row=2, column=0, sticky="e", pady=5)

pass_text = Label(main_frame, text="Password:", font=FONT, bg=BG_COLOR, fg=TEXT_COLOR)
pass_text.grid(row=3, column=0, sticky="e", pady=5)

# Entries
web_entry = Entry(main_frame, width=32, bg=ENTRY_BG, fg=TEXT_COLOR, font=FONT, relief=FLAT)
web_entry.focus()
web_entry.grid(row=1, column=1, pady=5)

name_entry = Entry(main_frame, width=32, bg=ENTRY_BG, fg=TEXT_COLOR, font=FONT, relief=FLAT)
name_entry.grid(row=2, column=1, columnspan=2, pady=5, sticky="ew")

pass_entry = Entry(main_frame, width=32, show="*", bg=ENTRY_BG, fg=TEXT_COLOR, font=FONT, relief=FLAT)
pass_entry.grid(row=3, column=1, pady=5)

# Buttons
button_style = {"font": FONT, "bg": BUTTON_COLOR, "fg": "white", "activebackground": "#3a6aac", "activeforeground": "white", "relief": FLAT, "borderwidth": 2}

search_bu = Button(main_frame, text="Search", width=10, command=search_pass, **button_style)
search_bu.grid(row=1, column=2, padx=(5, 0), pady=5)

gen_pass_bu = Button(main_frame, text="Generate", width=10, command=gen_pass, **button_style)
gen_pass_bu.grid(row=3, column=2, padx=(5, 0), pady=5)

add_bu = Button(main_frame, text="Add Credentials", width=30, command=add, **button_style)
add_bu.grid(row=5, column=1, columnspan=2, pady=(20, 5))

view_all_bu = Button(main_frame, text="View All Entries", width=30, command=view_all, **button_style)
view_all_bu.grid(row=6, column=1, columnspan=2, pady=5)

# Checkbox
show_pass_check = Checkbutton(main_frame, text="Show Password", command=toggle_password, bg=BG_COLOR, fg=TEXT_COLOR, font=FONT, activebackground=BG_COLOR)
show_pass_check.grid(row=4, column=1, sticky="w", pady=5)

change_pass_bu = Button(main_frame, text="Change Admin Password", width=30, command=change_admin_password, **button_style)
change_pass_bu.grid(row=7, column=1, columnspan=2, pady=5)

window.mainloop()