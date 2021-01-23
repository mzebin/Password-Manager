import tkinter as tk


# Functions


def encrypt(text):
	pass


def decrypt(text):
	pass


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
