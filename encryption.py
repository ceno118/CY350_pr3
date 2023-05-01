from cryptography.fernet import Fernet

KEY = Fernet.generate_key()

# I tried using this as a way to share a key between the two files but it didn't work as intended.