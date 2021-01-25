import pickle
import string
import tkinter as tk
from tkinter import messagebox

# Global Variables
SHIFT = 40
CHARACTERS = string.ascii_lowercase + \
             string.ascii_uppercase + \
             string.punctuation + \
             string.digits


# Classes

class Login:
    
    def __init__(self):
        # Create and configure Window
        self.login_window = tk.Tk()
        self.login_window.title("Password Manager - Login")
        self.login_window.resizable(0, 0)

        # Create Widgets

        self.username_label = tk.Label(self.login_window, text="Username:")
        self.username_label.grid(row=0, column=0, sticky="nsew")

        self.password_label = tk.Label(self.login_window, text="Password:")
        self.password_label.grid(row=1, column=0, sticky="nsew")

        self.username_entry = tk.Entry(self.login_window)
        self.username_entry.grid(row=0, column=1, sticky="nsew")

        self.password_entry = tk.Entry(self.login_window, show="*")
        self.password_entry.grid(row=1, column=1, sticky="nsew")

        self.login_btn = tk.Button(self.login_window, text="Login",
                                   command=self.validate_login)
        self.login_btn.grid(row=2, column=1, sticky="nsew")

        self.create_account_btn = tk.Button(self.login_window,
                                            text="Create Account",
                                            command=lambda: CreateAccount())
        self.create_account_btn.grid(row=2, column=0, sticky="nsew")

        # Key Bindings
        self.login_window.bind("<Return>", self.validate_login)

        # Start Mainloop
        self.login_window.mainloop()

    def validate_login(self, event=None):
        username = self.username_entry.get()
        password = self.password_entry.get()

        try:
            with open("Data Files/Users/users.dat", "rb") as file:
                users_info = pickle.load(file)
        except EOFError:
            messagebox.showerror("Password Manager - Error",
                                  "An unknown error occurred")

        if username in users_info:
            encrypted_password = users_info[username]
            decrypted_password = decrypt(encrypted_password)

            if password == decrypted_password:
                self.login_window.destroy()
                PasswordManager(username)
            else:
                messagebox.showerror("Password Manager - Error",
                                      "Incorrect Password.")
        else:
                messagebox.showerror("Password Manager - Error",
                                      "Incorrect Username.")


class CreateAccount:

    def __init__(self):
        # Create New Window
        self.new_window = tk.Tk()
        self.new_window.title("Password Manager - Create Account")
        self.new_window.resizable(0, 0)

        # Create Widgets

        self.username_label = tk.Label(self.new_window, text="Username:")
        self.username_label.grid(row=0, column=0, sticky="nsew")

        self.password_label1 = tk.Label(self.new_window, text="Password:")
        self.password_label1.grid(row=1, column=0, sticky="nsew")

        self.password_label2 = tk.Label(self.new_window,
                                        text="Confirm Password:")
        self.password_label2.grid(row=2, column=0, sticky="nsew")

        self.username_entry = tk.Entry(self.new_window)
        self.username_entry.grid(row=0, column=1, sticky="nsew")

        self.password_entry1 = tk.Entry(self.new_window, show="*")
        self.password_entry1.grid(row=1, column=1, sticky="nsew")

        self.password_entry2 = tk.Entry(self.new_window, show="*")
        self.password_entry2.grid(row=2, column=1, sticky="nsew")

        self.create_account_btn = tk.Button(self.new_window,
                                            text="Create Account",
                                            command=self.create_account)
        self.create_account_btn.grid(row=3, column=1, sticky="nsew")

        # Key Bindings
        self.new_window.bind("<Return>", self.create_account)

        # Start Mainloop
        self.new_window.mainloop()

    def create_account(self, event=None):
        username = self.username_entry.get()
        password1 = self.password_entry1.get()
        password2 = self.password_entry2.get()

        try:
            with open("Data Files/Users/users.dat", "rb") as file:
                users = pickle.load(file)
        except EOFError:
            if len(username) < 2:
                if password1 != password2:
                    messagebox.showerror("Password Manager - Error",
                                         "Passwords don't match.")
                elif len(password1) < 4:
                    messagebox.showerror("Password Manager - Error",
                                         "Passwords too short.")
                else:
                    users = {username: encrypt(password1)}
                    with open("Data Files/Users/users.dat", "wb") as file:
                        pickle.dump(users, file)
                        self.new_window.destroy()
            else:
                messagebox.showerror("Password Manager - Error",
                                     "Invalid Username")
        except FileNotFoundError:
            if len(username) > 2:
                if password1 != password2:
                    messagebox.showerror("Password Manager - Error",
                                         "Passwords don't match.")
                elif len(password1) < 4:
                    messagebox.showerror("Password Manager - Error",
                                         "Passwords too short.")
                else:
                    users = {username: encrypt(password1)}
                    with open("Data Files/Users/users.dat", "wb") as file:
                        pickle.dump(users, file)
                        self.new_window.destroy()
            else:
                messagebox.showerror("Password Manager - Error",
                                     "Invalid Username")

        else:
            if username not in users and len(username) > 2:
                if password1 != password2:
                    messagebox.showerror("Password Manager - Error",
                                         "Passwords don't match.")
                elif len(password1) < 4:
                    messagebox.showerror("Password Manager - Error",
                                         "Passwords too short.")
                else:
                    with open("Data Files/Users/users.dat", "rb") as file:
                        users = pickle.load(file)

                    users[username] = encrypt(password1)

                    with open("Data Files/Users/users.dat", "wb") as file:
                        pickle.dump(users, file)
                        self.new_window.destroy()
            else:
                messagebox.showerror("Password Manager - Error",
                                     "Invalid Username")

class PasswordManager:
    
    def __init__(self, user):
        # Create Window
        self.main_window = tk.Tk()
        self.main_window.title("Password Manager")
        self.main_window.resizable(0, 0)

        # Passwords File
        self.passwords_file = "Data Files/Passwords/passwords_" + user + ".dat"

        # Add Widgets

        # Add Password

        self.add_pass_entry = tk.Entry(self.main_window)
        self.add_pass_entry.grid(row=0, column=0, sticky="nsew", pady=(10, 5))

        self.add_pass_btn = tk.Button(self.main_window, text="Add a Password",
                                      command=self.add_password)
        self.add_pass_btn.grid(row=0, column=1, sticky="nsew", pady=(10, 5))

        # Update Password

        self.update_pass_entry = tk.Entry(self.main_window)
        self.update_pass_entry.grid(row=1, column=0, sticky="nsew", pady=(5, 5))

        self.update_pass_btn = tk.Button(self.main_window, 
                                         text="Update a Password",
                                         command=self.update_password)
        self.update_pass_btn.grid(row=1, column=1, sticky="nsew", pady=(5, 5))

        # Look Up Password

        self.lookup_pass_entry = tk.Entry(self.main_window)
        self.lookup_pass_entry.grid(row=2, column=0, sticky="nsew", pady=(5, 5))

        self.lookup_pass_btn = tk.Button(self.main_window,
                                         text="Look Up a Password",
                                         command=self.lookup_password)
        self.lookup_pass_btn.grid(row=2, column=1, sticky="nsew", pady=(5, 5))

        # Copy Password

        self.copy_pass_entry = tk.Entry(self.main_window)
        self.copy_pass_entry.grid(row=3, column=0, sticky="nsew", pady=(5, 5))

        self.copy_pass_btn = tk.Button(self.main_window, text="Copy a Password",
                                       command=self.copy_password)
        self.copy_pass_btn.grid(row=3, column=1, sticky="nsew", pady=(5, 5))

        # Delete a Password

        self.delete_pass_entry = tk.Entry(self.main_window)
        self.delete_pass_entry.grid(row=4, column=0, sticky="nsew",
                                    pady=(5, 10))

        self.delete_pass_btn = tk.Button(self.main_window,
                                         text="Delete a Password",
                                         command=self.delete_password)
        self.delete_pass_btn.grid(row=4, column=1, sticky="nsew", pady=(5, 10))

        # Start Mainloop
        self.main_window.mainloop()

    def add_password(self):
        def add_pass_to_file(event=None):
            key = self.add_pass_entry.get()
            password1 = password_entry1.get()
            password2 = password_entry2.get()

            if password1 != password2:
                messagebox.showerror("Password Manager - Error",
                                     "Passwords don't match.")
                self.lookup_pass_entry.delete(0, "end")

            try:
                with open(self.passwords_file, "rb") as file:
                    passwords = pickle.load(file)
            except EOFError:
                passwords = {key: encrypt(password1)}
                with open(self.passwords_file, "wb") as file:
                    pickle.dump(passwords, file)
                    new_window.destroy()
                    self.add_pass_entry.delete(0, "end")
            except FileNotFoundError:
                passwords = {key: encrypt(password1)}
                with open(self.passwords_file, "wb") as file:
                    pickle.dump(passwords, file)
                    new_window.destroy()
                    self.add_pass_entry.delete(0, "end")
            else:
                passwords[key] = encrypt(password1)
                with open(self.passwords_file, "wb") as file:
                    pickle.dump(passwords, file)
                    new_window.destroy()
                    self.add_pass_entry.delete(0, "end")


        try:
            with open(self.passwords_file, "rb") as file:
                passwords = pickle.load(file)
        except EOFError:
            passwords = {}
        except FileNotFoundError:
            passwords = {}
        finally:
            key = self.add_pass_entry.get()
            if key == "":
                messagebox.showwarning("Password Manager - Warning",
                                       "Bad Key")
                self.lookup_pass_entry.delete(0, "end")
                return
            elif key in passwords:
                messagebox.showerror("Password Manager - Error",
                                     "Alredy Exists")
                self.lookup_pass_entry.delete(0, "end")
                return
            else:
                # Create New window
                new_window = tk.Toplevel(self.main_window)

                # Add widgets
                password_label1 = tk.Label(new_window, text="Enter Password")
                password_label2 = tk.Label(new_window, text="Confirm Password")

                password_label1.grid(row=0, column=0, sticky="nsew")
                password_label2.grid(row=1, column=0, sticky="nsew")

                password_entry1 = tk.Entry(new_window, show="*")
                password_entry2 = tk.Entry(new_window, show="*")

                password_entry1.grid(row=0, column=1, sticky="nsew")
                password_entry2.grid(row=1, column=1, sticky="nsew")

                add_btn = tk.Button(new_window, text="Add",
                                           command=add_pass_to_file)
                add_btn.grid(row=2, column=1, sticky="nsew")

                # Key Bindings
                new_window.bind("<Return>", add_pass_to_file)


    def update_password(self):
        def update_pass(event=None):
            key = self.update_pass_entry.get()
            password1 = password_entry1.get()
            password2 = password_entry2.get()

            if password1 != password2:
                messagebox.showerror("Password Manager - Error",
                                     "Passwords don't match.")
                return
            else:
                passwords[key] = encrypt(password1)
                with open(self.passwords_file, "wb") as file:
                    pickle.dump(passwords, file)
                    new_window.destroy()
                    self.update_pass_entry.delete(0, "end")

        try:
            with open(self.passwords_file, "rb") as file:
                passwords = pickle.load(file)
        except EOFError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.update_pass_entry.delete(0, "end")
        except FileNotFoundError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.update_pass_entry.delete(0, "end")
        else:
            key = self.update_pass_entry.get()

            if key not in passwords:
                messagebox.showerror("Password Manager - Error",
                                     "Not Found")
                self.update_pass_entry.delete(0, "end")
                return
            else:
                # Create New window
                new_window = tk.Toplevel(self.main_window)

                # Add widgets
                password_label1 = tk.Label(new_window, text="Enter Password")
                password_label2 = tk.Label(new_window, text="Confirm Password")

                password_label1.grid(row=0, column=0, sticky="nsew")
                password_label2.grid(row=1, column=0, sticky="nsew")

                password_entry1 = tk.Entry(new_window, show="*")
                password_entry2 = tk.Entry(new_window, show="*")

                password_entry1.grid(row=0, column=1, sticky="nsew")
                password_entry2.grid(row=1, column=1, sticky="nsew")

                add_btn = tk.Button(new_window, text="Update",
                                           command=update_pass)
                add_btn.grid(row=2, column=1, sticky="nsew")

                # Key Bindings
                new_window.bind("<Return>", update_pass)

    def lookup_password(self):
        try:
            with open(self.passwords_file, "rb") as file:
                passwords = pickle.load(file)
        except EOFError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.lookup_pass_entry.delete(0, "end")
        except FileNotFoundError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.lookup_pass_entry.delete(0, "end")
        else:
            key = self.lookup_pass_entry.get()

            if key not in passwords:
                messagebox.showerror("Password Manager - Error",
                                     "Not Found")
                self.lookup_pass_entry.delete(0, "end")
                return
            else:
                encrypted_password = passwords[key]
                decrypted_password = decrypt(encrypted_password)

                messagebox.showinfo("Password Manager",
                                    f"{key}: {decrypted_password}")
                self.lookup_pass_entry.delete(0, "end")

    def copy_password(self):
        try:
            with open(self.passwords_file, "rb") as file:
                passwords = pickle.load(file)
        except EOFError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.copy_pass_entry.delete(0, "end")
        except FileNotFoundError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.copy_pass_entry.delete(0, "end")
        else:
            key = self.copy_pass_entry.get()

            if key not in passwords:
                messagebox.showerror("Password Manager - Error",
                                     "Not Found")
                self.copy_pass_entry.delete(0, "end")
                return
            else:
                encrypted_password = passwords[key]
                decrypted_password = decrypt(encrypted_password)

                self.main_window.clipboard_clear()
                self.main_window.clipboard_append(decrypted_password)

                messagebox.showinfo("Password Manager",
                                    "Password copied to clipboard.")
                self.copy_pass_entry.delete(0, "end")

    def delete_password(self):
        try:
            with open(self.passwords_file, "rb") as file:
                passwords = pickle.load(file)
        except EOFError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.delete_pass_entry.delete(0, "end")
        except FileNotFoundError:
            messagebox.showerror("Password Manager - Error",
                                 "Not Found")
            self.delete_pass_entry.delete(0, "end")
        else:
            key = self.delete_pass_entry.get()

            if key not in passwords:
                messagebox.showerror("Password Manager - Error",
                                     "Not Found")
                self.delete_pass_entry.delete(0, "end")
                return
            else:
                response = messagebox.askokcancel("Password Manager",
                                       "This item will be deleted" + \
                                       " immediately. You can’t" +\
                                       " undo this action")
                
                if response:
                    del passwords[key]

                    with open(self.passwords_file, "wb") as file:
                        pickle.dump(passwords, file)
                        messagebox.showinfo("Password Manager",
                                            "Password deleted successfully")
                        self.delete_pass_entry.delete(0, "end")
                else:
                    self.delete_pass_entry.delete(0, "end")

# Functions

def encrypt(text, shift=SHIFT):
    shifted = CHARACTERS[shift:] + CHARACTERS[:shift]
    table = str.maketrans(CHARACTERS, shifted)

    encrypted = text.translate(table)
    return encrypted


def decrypt(text, shift=SHIFT):
    shifted = CHARACTERS[shift:] + CHARACTERS[:shift]
    table = str.maketrans(shifted, CHARACTERS)

    decrypted = text.translate(table)
    return decrypted


def main():
    try:
        with open("Data Files/Users/users.dat", "rb") as file:
            users = pickle.load(file)
    except EOFError:
        CreateAccount()
        Login()
    except FileNotFoundError:
        CreateAccount()
        Login()
    else:
        Login()


if __name__ == "__main__":
    main()
