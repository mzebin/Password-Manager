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
		# Create and configre Window
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

		self.login_btn = tk.Button(self.login_window, text="Login", command=self.validate_login)
		self.login_btn.grid(row=2, column=1, sticky="nsew")

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

		self.password_label2 = tk.Label(self.new_window, text="Confirm Password:")
		self.password_label2.grid(row=2, column=0, sticky="nsew")

		self.username_entry = tk.Entry(self.new_window)
		self.username_entry.grid(row=0, column=1, sticky="nsew")

		self.password_entry1 = tk.Entry(self.new_window, show="*")
		self.password_entry1.grid(row=1, column=1, sticky="nsew")

		self.password_entry2 = tk.Entry(self.new_window, show="*")
		self.password_entry2.grid(row=2, column=1, sticky="nsew")

		self.create_account_btn = tk.Button(self.new_window, text="Create Account", command=self.create_account)
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

		# Passwords File
		self.passwords_file = "Data Files/Passwords/passwords_" + user + ".dat"

		# Start Mainloop
		self.main_window.mainloop()


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
