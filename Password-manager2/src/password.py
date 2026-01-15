import os
import sqlite3, sqlcipher3
import base64
import hashlib
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes  # Importation de hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Définir le chemin de la base de données dans le dossier db/
# DB_FOLDER =('db')
DB_FOLDER = os.path.dirname(os.path.abspath(__file__))

dir_database = os.path.join(DB_FOLDER, "db")

os.makedirs(dir_database, exist_ok=True)

DATABASE = os.path.join(dir_database, "password_manager.db")
DB_PASSWORD = os.getenv("DB_PASSWORD")


# Fonction pour créer la base de données et les tables
def init_db():
    conn = sqlcipher3.connect(DATABASE)
    cursor = conn.cursor()

    # Appliquez le mot de passe pour déchiffrer la base
    cursor.execute(f"PRAGMA key = '{DB_PASSWORD}';")


    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            master_password TEXT,
                            salt TEXT
                        )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                            username TEXT,
                            label TEXT,
                            encrypted_password TEXT,
                            FOREIGN KEY(username) REFERENCES users(username)
                        )''')
    conn.commit()
    conn.close()
    print(f"Database created at {DATABASE}")



# Fonction pour enregistrer un nouvel utilisateur
def register_user(username, master_password):
    conn = sqlcipher3.connect(DATABASE)
    cursor = conn.cursor()

    # Appliquez le mot de passe pour déchiffrer la base
    cursor.execute(f"PRAGMA key = '{DB_PASSWORD}';")

    # Vérifier si l'utilisateur existe déjà
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        print("Erreur: User existe déjà.")
        conn.close()
        return

    # Générer un sel
    salt = os.urandom(16)
    # Créer le mot de passe salé
    salted_password = master_password.encode() + salt
    # Hacher le mot de passe avec SHA-256
    hashed_password = hashlib.sha256(salted_password).digest()
    # Enregistrer en base64
    encoded_password = base64.b64encode(hashed_password).decode()
    encoded_salt = base64.b64encode(salt).decode()

    try:
        cursor.execute('INSERT INTO users (username, master_password, salt) VALUES (?, ?, ?)',
                       (username, encoded_password, encoded_salt))
        conn.commit()
        print(f"User '{username}' successfully saved!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


# Vérification de la force du mot de passe
def check_password_strength(password):
    """Vérifie la force du mot de passe."""
    # Vérification de la longueur minimale de 8 caractères
    if len(password) < 8:
        return "Mot de passe trop court, doit contenir au moins 8 caractères."

    # Vérification de la présence d'une majuscule
    if not re.search(r"[A-Z]", password):
        return "Le mot de passe doit contenir au moins une majuscule."

    # Vérification de la présence d'une minuscule
    if not re.search(r"[a-z]", password):
        return "Le mot de passe doit contenir au moins une minuscule."

    # Vérification de la présence d'un chiffre
    if not re.search(r"[0-9]", password):
        return "Le mot de passe doit contenir au moins un chiffre."

    # Vérification de la présence d'un caractère spécial
    if not re.search(r"[\W_]", password):  # Caractères spéciaux
        return "Le mot de passe doit contenir au moins un caractère spécial."
    # Si toutes les conditions sont satisfaites
    return "Mot de passe fort."


# Fonction pour dériver la clé AES à partir du mot de passe principal
def derive_key(master_password, salt):
    # Dérivation de la clé avec PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())  # Pas besoin de base64 ici


# Fonction pour ajouter un mot de passe
def add_password(username, master_password, label, plain_text_password):
    conn = sqlcipher3.connect(DATABASE)
    cursor = conn.cursor()

    # Appliquez le mot de passe pour déchiffrer la base
    cursor.execute(f"PRAGMA key = '{DB_PASSWORD}';")


    cursor.execute('SELECT master_password, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        print("Error: User not registered.")
        return

    stored_password, stored_salt = user
    salt = base64.b64decode(stored_salt)
    derived_key = derive_key(master_password, salt)

    # Chiffrement du mot de passe avec AES-256
    iv = os.urandom(16)  # Générer un vecteur d'initialisation
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = iv + encryptor.update(plain_text_password.encode()) + encryptor.finalize()

    # Enregistrer le mot de passe chiffré en base64
    encoded_encrypted_password = base64.b64encode(encrypted_password).decode()

    try:
        cursor.execute('INSERT INTO passwords (username, label, encrypted_password) VALUES (?, ?, ?)',
                       (username, label, encoded_encrypted_password))
        conn.commit()
        print(f"Password '{label}' successfully saved!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


# Fonction pour afficher un mot de passe
def show_password(username, master_password, label):
    conn = sqlcipher3.connect(DATABASE)
    cursor = conn.cursor()

    # Appliquez le mot de passe pour déchiffrer la base
    cursor.execute(f"PRAGMA key = '{DB_PASSWORD}';")


    cursor.execute('SELECT master_password, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        print("Error: User not registered.")
        return

    stored_password, stored_salt = user
    salt = base64.b64decode(stored_salt)
    derived_key = derive_key(master_password, salt)

    cursor.execute('SELECT encrypted_password FROM passwords WHERE username = ? AND label = ?',
                   (username, label))
    password_record = cursor.fetchone()

    if not password_record:
        print("Error: Password label not found.")
        return

    encrypted_password = base64.b64decode(password_record[0])

    # Extraire le vecteur d'initialisation
    iv = encrypted_password[:16]
    encrypted_data = encrypted_password[16:]

    # Déchiffrer le mot de passe
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain_text_password = decryptor.update(encrypted_data) + decryptor.finalize()

    print(f"Password '{label}' is: {plain_text_password.decode()}")


# Fonction pour modifier un mot de passe existant
def modify_password(username, master_password, label, new_password):
    conn = sqlcipher3.connect(DATABASE)
    cursor = conn.cursor()

    # Appliquez le mot de passe pour déchiffrer la base
    cursor.execute(f"PRAGMA key = '{DB_PASSWORD}';")


    cursor.execute('SELECT master_password, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        print("Error: User not registered.")
        return

    stored_password, stored_salt = user
    salt = base64.b64decode(stored_salt)
    derived_key = derive_key(master_password, salt)

    cursor.execute('SELECT encrypted_password FROM passwords WHERE username = ? AND label = ?',
                   (username, label))
    password_record = cursor.fetchone()

    if not password_record:
        print(f"Error: Password label '{label}' not found.")
        return

    # Vérification de la force du nouveau mot de passe
    password_strength = check_password_strength(new_password)
    if password_strength != "Mot de passe fort.":
        print(password_strength)
        return

    encrypted_password = base64.b64decode(password_record[0])

    # Extraire le vecteur d'initialisation
    iv = encrypted_password[:16]
    encrypted_data = encrypted_password[16:]

    # Déchiffrer le mot de passe existant pour validation
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    old_password = decryptor.update(encrypted_data) + decryptor.finalize()

    # Chiffrement du nouveau mot de passe
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_new_password = iv + encryptor.update(new_password.encode()) + encryptor.finalize()

    encoded_encrypted_new_password = base64.b64encode(encrypted_new_password).decode()

    try:
        cursor.execute('UPDATE passwords SET encrypted_password = ? WHERE username = ? AND label = ?',
                       (encoded_encrypted_new_password, username, label))
        conn.commit()
        print(f"Password for '{label}' successfully modified!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


# Fonction pour supprimer un mot de passe spécifique
def delete_password(username, master_password, label):
    conn = sqlcipher3.connect(DATABASE)
    cursor = conn.cursor()

    # Appliquez le mot de passe pour déchiffrer la base
    cursor.execute(f"PRAGMA key = '{DB_PASSWORD}';")


    cursor.execute('SELECT master_password, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        print("Error: User not registered.")
        return

    stored_password, stored_salt = user
    salt = base64.b64decode(stored_salt)
    derived_key = derive_key(master_password, salt)

    cursor.execute('SELECT encrypted_password FROM passwords WHERE username = ? AND label = ?',
                   (username, label))
    password_record = cursor.fetchone()

    if not password_record:
        print(f"Error: Password label '{label}' not found.")
        return

    try:
        cursor.execute('DELETE FROM passwords WHERE username = ? AND label = ?',
                       (username, label))
        conn.commit()
        print(f"Password for '{label}' successfully deleted!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


# Fonction pour supprimer un compte utilisateur
def delete_user(username, master_password):
    conn = sqlcipher3.connect(DATABASE)
    cursor = conn.cursor()

    # Appliquez le mot de passe pour déchiffrer la base
    cursor.execute(f"PRAGMA key = '{DB_PASSWORD}';")


    cursor.execute('SELECT master_password, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        print("Error: User not registered.")
        return

    stored_password, stored_salt = user
    salt = base64.b64decode(stored_salt)
    derived_key = derive_key(master_password, salt)

    # Vérification du mot de passe maître
    if stored_password != base64.b64encode(hashlib.sha256(master_password.encode() + salt).digest()).decode():
        print("Error: Incorrect master password.")
        return

    try:
        # Supprimer tous les mots de passe de cet utilisateur
        cursor.execute('DELETE FROM passwords WHERE username = ?', (username,))
        # Supprimer l'utilisateur
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        print(f"User '{username}' and all associated passwords successfully deleted!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


# Fonction principale pour gérer la CLI
def main():
    import sys

    if len(sys.argv) < 3:
        print(
            "Usage: passmanager -r <username> <master_password> OR passmanager -u <username> -a <label> <password> OR passmanager -u <username> -s <label> OR passmanager -u <username> -m <label> <new_password> OR passmanager -u <username> -d <label> OR passmanager -d <username> <master_password>")
        return

    command = sys.argv[1]

    if command == "-r" and len(sys.argv) == 3:
        username = sys.argv[2]
        master_password = input(f"Enter {username}'s master password: ")
        register_user(username, master_password)

    elif command == "-u" and len(sys.argv) >= 5:
        username = sys.argv[2]
        action = sys.argv[3]

        if action == "-a" and len(sys.argv) == 6:
            label = sys.argv[4]
            password = sys.argv[5]
            master_password = input(f"Enter {username}'s master password: ")
            add_password(username, master_password, label, password)

        elif action == "-s" and len(sys.argv) == 5:
            label = sys.argv[4]
            master_password = input(f"Enter {username}'s master password: ")
            show_password(username, master_password, label)

        elif action == "-m" and len(sys.argv) == 6:
            label = sys.argv[4]
            new_password = sys.argv[5]
            master_password = input(f"Enter {username}'s master password: ")
            modify_password(username, master_password, label, new_password)

        elif action == "-d" and len(sys.argv) == 5:
            label = sys.argv[4]
            master_password = input(f"Enter {username}'s master password: ")
            delete_password(username, master_password, label)

        else:
            print("Invalid command.")

    elif command == "-d" and len(sys.argv) == 4:
        username = sys.argv[2]
        master_password = input(f"Enter {username}'s master password: ")
        delete_user(username, master_password)

    else:
        print("Invalid command.")


# Initialisation de la base de données
init_db()

# Appel de la fonction principale
if __name__ == "__main__":
    main()