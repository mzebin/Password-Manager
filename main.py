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

	def validate_login(self, event):
		username = self.username_entry.get()
		password = self.password_entry.get()

		try:
			with open("Data Files/users.dat", "rb") as file:
				users_info = pickle.load(file)
		except EOFError:
			messagebox.showerror("PasswordManger - Error",
								  "An unknown error occurred")

		if username in users_info:
			encrypted_password = users_info[username]
			decrypted_password = decrypt(encrypted_password)

			if password == decrypted_password:
				self.login_window.destroy()
				PasswordManger()
			else:
				messagebox.showerror("PasswordManger - Error", 
									  "Incorrect Password.")
		else:
				messagebox.showerror("PasswordManger - Error", 
									  "Incorrect Username.")


class PasswordManger:
	
	def __init__(self):
		# Create Window
		self.main_window = tk.Tk()

		# Start Mainloop
		self.main_window.mainloop()


if __name__ == "__main__":
	Login()
