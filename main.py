import string
import tkinter as tk

# Global Variables
SHIFT = 40

lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
punctuation = string.punctuation
digits = string.digits

CHARACTERS = lowercase + uppercase + punctuation + digits


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

		self.create_acc_btn = tk.Button(self.login_window, text="Create Account", command=self.create_account)
		self.create_acc_btn.grid(row=2, column=0, sticky="nsew")

		self.login_btn = tk.Button(self.login_window, text="Login", command=self.validate_login)
		self.login_btn.grid(row=2, column=1, sticky="nsew")

		# Start Mainloop
		self.login_window.mainloop()

	def validate_login(self):
		pass

	def create_account(self):
		pass


class PasswordManger:
	
	def __init__(self):
		pass


if __name__ == "__main__":
	Login()
