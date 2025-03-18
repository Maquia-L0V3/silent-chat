# silent-chat
A secure, peer-to-peer cli chat system built in Python, featuring E2EE to ensure secure messaging. This system uses RSA for public/private key encryption and AES for message encryption.

## Features

- **Peer-to-peer communication**: No central server; all messages are sent directly between peers, one of them directly acting as a server.
- **End-to-End Encryption (E2EE)**: Messages are encrypted on the sender's side and decrypted on the receiver's side.
- **RSA Encryption**: Public and private keys used for securely sharing an AES key for encrypting the messages.
- **AES Encryption**: Symmetric encryption for message payloads using a 256-bit key and CBC mode.
- **Message Integrity**: Secure and tamper-proof message transmission.
- **Debug System**: Toggleable debug messages.
  
## Prerequisites

- Python 3.x

## Installation

1. Clone the repository:

    **git clone https://github.com/Maquia-L0V3/silent-chat.git**

2. Navigate to the project directory:

    **cd silent-chat**

3. Install the required dependencies:

    **pip install -r requirements.txt**

## How to Use

1. **Run as a Server**:

    To start the chat as the server (waiting for a peer to connect):

    - Start the **main.py** file normally
    - Enter the desired port to host the server.
    - Wait for a client to connect.

2. **Run as a Client**:

    To start the chat as a client (connecting to a server):

    - Start the **main.py** file normally
    - Enter the server's IP address and port.
    - You'll be connected to the server.

3. **Start Messaging**:
    - Both peers can now send and receive encrypted messages. Messages are decrypted only on the receiver’s side.
    
## How It Works

1. **Key Exchange**:
    - Both peers generate their RSA key pairs.
    - Public keys are exchanged between peers to securely share the AES encryption key and IV.
    - The AES key and IV are encrypted using the recipient's RSA public key and sent over the P2P connection.

2. **Message Encryption**:
    - After the AES key and IV exchange, all messages are encrypted using the AES key in CBC mode.
    - The encrypted message is sent through the P2P connection.

3. **Message Decryption**:
    - Upon receiving a message, the AES key and IV are used to decrypt the message content. 
    - Messages are then displayed to the user.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
