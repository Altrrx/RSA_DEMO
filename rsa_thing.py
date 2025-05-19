import sympy
import random
import logging
import os

LOG_FILE = "rsa_log.txt"
logging_enabled = True

def setup_logger():
    if logging_enabled:
        logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(message)s')
        logging.info("=== RSA Multitool Log ===")
    else:
        logging.getLogger().handlers.clear()

def generate_keys():
    p = sympy.randprime(100, 500)
    q = sympy.randprime(100, 500)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while sympy.gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = sympy.mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(msg, pubkey):
    e, n = pubkey
    return [pow(ord(c), e, n) for c in msg]

def decrypt(cipher, privkey):
    d, n = privkey
    try:
        return ''.join(chr(pow(c, d, n)) for c in cipher)
    except:
        return "[Decryption Failed]"

def log(text):
    if logging_enabled:
        logging.info(text)

def get_keys_from_user():
    print("Enter keys separated by space:")
    e_or_d = int(input("Enter e (public) or d (private): "))
    n = int(input("Enter n: "))
    return (e_or_d, n)

def menu():
    global logging_enabled

    while True:
        print("\nRSA Multitool Menu:")
        print("1. Generate keys")
        print("2. Encrypt message")
        print("3. Decrypt message")
        print("4. Toggle logging (currently {})".format("ON" if logging_enabled else "OFF"))
        print("5. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            pubkey, privkey = generate_keys()
            print(f"Public Key (e, n): {pubkey}")
            print(f"Private Key (d, n): {privkey}")
            log(f"Generated keys:\nPublic: {pubkey}\nPrivate: {privkey}")

        elif choice == "2":
            pubkey = get_keys_from_user()
            msg = input("Enter message to encrypt: ")
            cipher = encrypt(msg, pubkey)
            print("Ciphertext:", cipher)
            log(f"Encrypted message: '{msg}' with public key {pubkey}")
            log(f"Ciphertext: {cipher}")

        elif choice == "3":
            privkey = get_keys_from_user()
            cipher_input = input("Enter ciphertext (comma-separated integers): ")
            try:
                cipher = [int(x.strip()) for x in cipher_input.split(",")]
            except:
                print("Invalid ciphertext format!")
                continue
            decrypted = decrypt(cipher, privkey)
            print("Decrypted message:", decrypted)
            log(f"Decrypted ciphertext {cipher} with private key {privkey}")
            log(f"Decrypted message: {decrypted}")

        elif choice == "4":
            logging_enabled = not logging_enabled
            if logging_enabled:
                setup_logger()
                print("Logging enabled. Logs will be saved to", LOG_FILE)
            else:
                logging.getLogger().handlers.clear()
                print("Logging disabled.")

        elif choice == "5":
            print("Exiting RSA Multitool.")
            break
        else:
            print("Invalid choice! Try again.")

if __name__ == "__main__":
    setup_logger()
    menu()
