import sympy
import random
import logging
import os

LOG_FILE = "rsa_log.txt"
logging_enabled = True
math_visuals = True

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def setup_logger():
    if logging_enabled:
        logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(message)s')
        logging.info("=== RSA Multitool Log ===")
    else:
        logging.getLogger().handlers.clear()

def log(text):
    if logging_enabled:
        logging.info(text)

def generate_keys(verbose=math_visuals):
    p = sympy.randprime(100, 500)
    q = sympy.randprime(100, 500)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while sympy.gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = sympy.mod_inverse(e, phi)

    if verbose:
        print(f"Generating keys:")
        print(f"  p = {p}")
        print(f"  q = {q}")
        print(f"  n = p * q = {n}")
        print(f"  phi(n) = (p-1)*(q-1) = {phi}")
        print(f"  Choose e = {e} (public exponent)")
        print(f"  Compute d = e^(-1) mod phi(n) = {d} (private exponent)")
        print(f"Public key: (e={e}, n={n})")
        print(f"Private key: (d={d}, n={n})")

    log(f"Generated keys:\np={p}, q={q}, n={n}, phi={phi}, e={e}, d={d}")
    return ((e, n), (d, n))

def encrypt(msg, pubkey, verbose=math_visuals):
    e, n = pubkey
    cipher = []
    if verbose:
        print(f"\nEncrypting message '{msg}' with public key (e={e}, n={n}):")
    for c in msg:
        m = ord(c)
        ciph = pow(m, e, n)
        cipher.append(ciph)
        if verbose:
            print(f"  '{c}' -> ASCII {m}: ciphertext = {m}^{e} mod {n} = {ciph}")
    log(f"Encrypted message '{msg}' with public key {pubkey}: {cipher}")
    return cipher

def decrypt(cipher, privkey, verbose=math_visuals):
    d, n = privkey
    decrypted_chars = []
    if verbose:
        print(f"\nDecrypting ciphertext {cipher} with private key (d={d}, n={n}):")
    for ciph in cipher:
        m = pow(ciph, d, n)
        try:
            char = chr(m)
        except:
            char = '?'
        decrypted_chars.append(char)
        if verbose:
            print(f"  ciphertext {ciph}: {ciph}^{d} mod {n} = {m} -> '{char}'")
    decrypted_msg = ''.join(decrypted_chars)
    log(f"Decrypted ciphertext {cipher} with private key {privkey}: '{decrypted_msg}'")
    return decrypted_msg

def get_keys_from_user():
    print("Enter keys separated by space:")
    e_or_d = int(input("Enter e (public) or d (private): "))
    n = int(input("Enter n: "))
    return (e_or_d, n)

def menu():
    global logging_enabled, math_visuals

    while True:
        clear_console()
        print("=== RSA Multitool ===")
        print(f"Logging: {'ON' if logging_enabled else 'OFF'} | Math visuals: {'ON' if math_visuals else 'OFF'}\n")
        print("1. Generate keys")
        print("2. Encrypt message")
        print("3. Decrypt message")
        print("4. Toggle logging")
        print("5. Toggle math visuals")
        print("6. Exit")

        choice = input("Choose an option: ").strip()

        clear_console()

        if choice == "1":
            pubkey, privkey = generate_keys()
            print(f"\nSave your keys somewhere safe!")
            log(f"Generated keys:\nPublic: {pubkey}\nPrivate: {privkey}")

        elif choice == "2":
            pubkey = get_keys_from_user()
            msg = input("Enter message to encrypt: ")
            cipher = encrypt(msg, pubkey)
            print("Ciphertext:", cipher)

        elif choice == "3":
            privkey = get_keys_from_user()
            cipher_input = input("Enter ciphertext (comma-separated integers): ")
            try:
                cipher = [int(x.strip()) for x in cipher_input.split(",")]
            except:
                print("Invalid ciphertext format!")
                input("Press enter to continue...")
                continue
            decrypted = decrypt(cipher, privkey)
            print("Decrypted message:", decrypted)

        elif choice == "4":
            logging_enabled = not logging_enabled
            if logging_enabled:
                setup_logger()
                print("Logging enabled. Logs will be saved to", LOG_FILE)
            else:
                logging.getLogger().handlers.clear()
                print("Logging disabled.")

        elif choice == "5":
            math_visuals = not math_visuals
            print(f"Math visuals {'enabled' if math_visuals else 'disabled'}.")

        elif choice == "6":
            print("Exiting RSA Multitool.")
            break
        else:
            print("Invalid choice! Try again.")

        input("\nPress enter to return to menu...")

if __name__ == "__main__":
    setup_logger()
    menu()
