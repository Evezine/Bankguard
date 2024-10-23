import streamlit as st
import socket
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import threading
import json
import os

# Generate RSA key pair for signing
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Message storage
message_history = []

# Function to sign a message
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

# Function to verify the digital signature
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            bytes.fromhex(signature),
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Server function to handle incoming message requests
def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12347))  # Port for the server
    server_socket.listen(1)
    print("Server is listening on port 12347...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        
        # Receive data
        data = conn.recv(1024).decode('utf-8')
        message, hash_value, signature = data.split('|')

        # Verify the hash
        hashed_message = hashlib.sha256(message.encode()).hexdigest()
        
        if hashed_message == hash_value and verify_signature(public_key, message.encode(), signature):
            response = "Message verified successfully!"
        else:
            response = "Message verification failed!"
        
        conn.send(response.encode())
        conn.close()

# Start the server in a separate thread
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()

# Streamlit application interface
st.title("VerifyChat - Message Verification System")

# Client input
message = st.text_input("Enter your message:")
if st.button("Send Message"):
    if message:
        # Hash the message
        hash_value = hashlib.sha256(message.encode()).hexdigest()
        
        # Sign the message
        signature = sign_message(private_key, message.encode())

        # Send the message, hash, and signature to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(('localhost', 12347))  # Connect to the server
            data_to_send = f"{message}|{hash_value}|{signature}"
            client_socket.send(data_to_send.encode())

            # Receive the response from the server
            response = client_socket.recv(1024).decode('utf-8')
            st.write(f"Server Response: {response}")

        # Add to message history
        message_history.append({
            "message": message,
            "hash": hash_value,
            "signature": signature
        })
        
        # Display hash and signature
        st.write(f"Hash: {hash_value}")
        st.write(f"Signature: {signature}")

    else:
        st.error("Please enter a message.")

# Display message history
if st.button("Show Message History"):
    if message_history:
        st.write("Message History:")
        for msg in message_history:
            st.write(f"Message: {msg['message']}")
            st.write(f"Hash: {msg['hash']}")
            st.write(f"Signature: {msg['signature']}")
            st.write("---")
    else:
        st.write("No messages sent yet.")
