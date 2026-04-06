# encrypt_cheat.py
# Lance ce script UNE FOIS en local dans le même dossier que CHEAT.exe
# Puis upload CHEAT.enc dans ton repo GitHub (Railway le déploiera)

import base64, hashlib
from cryptography.fernet import Fernet

KEY         = b"araxis_secret_key_32bytes_padding"
fernet_key  = base64.urlsafe_b64encode(hashlib.sha256(KEY).digest())
f           = Fernet(fernet_key)

with open("CHEAT.exe", "rb") as file:
    encrypted = f.encrypt(file.read())

with open("CHEAT.enc", "wb") as file:
    file.write(encrypted)

print("CHEAT.enc cree — upload ce fichier dans ton repo GitHub")
print("Ne partage JAMAIS la cle de chiffrement")
