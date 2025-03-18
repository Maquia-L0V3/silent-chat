import socket
import threading
import os
import sys
try:
    import readline
except ImportError:
    readline = None

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

names = ['Local', 'Other']

debug = True

def debug_print(message):
    if debug == False:
        return
    print(f"[DEBUG] {message}")

def create_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    debug_print("RSA keys generated.")
    return private_key, public_key

def create_aes_cipher():
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    debug_print(f"AES key generated: {aes_key.hex()}")
    debug_print(f"IV generated: {iv.hex()}")
    return cipher, aes_key, iv

def encrypt_rsa(data, public_key):
    encrypted_data = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_rsa(encrypted_data, private_key):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

def encrypt_data(plain_text, cipher):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text) + padder.finalize()
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text

def decrypt_data(cipher_text, cipher):
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain_text = unpadder.update(decrypted_data) + unpadder.finalize()
    return plain_text

def receive_messages(connection, cipher):
    while True:
        try:
            data = connection.recv(1024)
            if not data:
                print("\nConnection closed.")
                break
            decrypted_data = decrypt_data(data, cipher)
            current_line = readline.get_line_buffer() if readline else ""
            sys.stdout.write("\r" + " " * (len(current_line) + 20) + "\r")
            print(f"\n{names[1]}: {decrypted_data.decode()}")
            sys.stdout.write(f"\n{names[0]}: {current_line}")
            sys.stdout.flush()
        except socket.error as e:
            print("Receive error:", e)
            break
    connection.close()

def send_messages(connection, cipher):
    while True:
        try:
            msg = input(f"\n{names[0]}: ")
            encrypted_msg = encrypt_data(msg.encode(), cipher)
            connection.sendall(encrypted_msg)
        except socket.error as e:
            print("Send error:", e)
            break
    connection.close()

hosting = int(input("Connect as Client (1)\nHost as Server (2)\n"))

if hosting == 1:
    # CLIENT
    address = input("\nInput server address (ip:port)\n")
    ip = address.split(":")
    ip[1] = int(ip[1])
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip[0], ip[1]))
    print(f"Connected to {ip[0]}:{ip[1]}")
    debug_print("Client connected to server.")

    client_private_key, client_public_key = create_rsa_keys()
    client_socket.sendall(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    debug_print("Client public key sent.")

    server_public_key_data = client_socket.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_key_data)
    debug_print("Server public key received.")

    cipher, aes_key, iv = create_aes_cipher()
    aes_payload = aes_key + iv  # 32 + 16 bytes = 48 bytes total.
    debug_print("AES payload created (key + IV).")
    encrypted_aes_payload = encrypt_rsa(aes_payload, server_public_key)
    client_socket.sendall(encrypted_aes_payload)
    debug_print("Encrypted AES payload sent to server.")

    threading.Thread(target=receive_messages, args=(client_socket, cipher), daemon=True).start()
    send_messages(client_socket, cipher)

else:
    # SERVER
    port = int(input("\nInput preferred port for hosting\n"))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(1)
    print(f"\nListening for connection on 0.0.0.0:{port}...\n")
    connection, addr = server_socket.accept()
    print(f"\nConnected from {addr}\n")
    debug_print("Server accepted a connection.")

    server_private_key, server_public_key = create_rsa_keys()
    connection.sendall(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    debug_print("Server public key sent.")

    client_public_key_data = connection.recv(2048)
    client_public_key = serialization.load_pem_public_key(client_public_key_data)
    debug_print("Client public key received.")

    encrypted_aes_payload = connection.recv(1024)
    aes_payload = decrypt_rsa(encrypted_aes_payload, server_private_key)
    aes_key = aes_payload[:32]
    iv = aes_payload[32:48]
    debug_print("AES payload decrypted on server.")
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    debug_print("AES cipher created on server.")

    threading.Thread(target=receive_messages, args=(connection, cipher), daemon=True).start()
    send_messages(connection, cipher)
