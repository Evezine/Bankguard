import streamlit as st
import socket
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import threading

# Generate RSA key pair for signing
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Function to sign a transaction message
def sign_transaction(private_key, transaction):
    signature = private_key.sign(
        transaction,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

# Function to verify the digital signature
def verify_signature(public_key, transaction, signature):
    try:
        public_key.verify(
            bytes.fromhex(signature),
            transaction,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Server function to handle incoming transaction requests
def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server is listening on port 12345...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        
        # Receive data
        data = conn.recv(1024).decode('utf-8')
        transaction, hash_value, signature = data.split('|')

        # Verify the hash
        hashed_transaction = hashlib.sha256(transaction.encode()).hexdigest()
        
        if hashed_transaction == hash_value and verify_signature(public_key, transaction.encode(), signature):
            response = "Transaction verified successfully!"
        else:
            response = "Transaction verification failed!"
        
        conn.send(response.encode())
        conn.close()

# Start the server in a separate thread
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()

# Streamlit application interface
st.title("BankGuard - Online Banking System")

# Client input
transaction = st.text_input("Enter transaction details (e.g., 'Transfer $100 to Account 12345'):")
if st.button("Submit Transaction"):
    if transaction:
        # Hash the transaction
        hash_value = hashlib.sha256(transaction.encode()).hexdigest()
        
        # Sign the transaction
        signature = sign_transaction(private_key, transaction.encode())

        # Send the transaction, hash, and signature to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(('localhost', 12345))
            data_to_send = f"{transaction}|{hash_value}|{signature}"
            client_socket.send(data_to_send.encode())

            # Receive the response from the server
            response = client_socket.recv(1024).decode('utf-8')
            st.write(f"Server Response: {response}")

        # Display hash and signature
        st.write(f"Hash: {hash_value}")
        st.write(f"Signature: {signature}")

    else:
        st.error("Please enter transaction details.")
