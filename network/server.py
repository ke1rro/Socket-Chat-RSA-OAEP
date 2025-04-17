"""
Chat server module
"""

import socket
import threading

from connection import Connection

from cryptography.rsa import RSAKeyPair
from protocol.secure_msg import SecureMessage


class ChatServer:
    """
    Class the handles thread safely the connected sockets
    """

    hos: str
    address: int

    def __init__(self, host: str = "127.0.0.1", address: int = 10000):
        self.address = address
        self.rsa: RSAKeyPair = RSAKeyPair()
        self.clients: dict[Connection, str] = {}

    def start(self) -> None:
        """
        Starts the server and handles the connections on separete thread
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # To prevent socket timeout
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind(self.address)
        sock.listen()
        print(f"Server is working on {self.address}")

        while True:
            client_sock, _ = sock.accept()
            conn = Connection(client_sock, rsa=None, pubkey=None)
            threading.Thread(
                target=self.handle_connection, args=(conn,), deamon=True
            ).start()

    def handle_handshake(self, conn: Connection) -> None:
        """
        Exchanges the public key with the client.

        Args:
            conn (Connection): The client connection object.
        """
        # client handshake
        raw = conn.sock.recv(4096).decode()
        n, e = map(int, raw.split(","))
        conn.remote_pubkey = (n, e)
        sn, se = self.rsa.pubcli_key()
        conn.sock.sendall(f"{sn}, {se}".encode())
        conn.rsa = self.rsa

    def handle_connection(self, conn: Connection) -> None:
        """
        Handles each user (socket connection) on separeted thread
        and introducing user to whole chatroom.

        Args:
            conn (Connection): The new user's connection object
        """
        self.handle_handshake(conn)

        # username
        msg = conn.recv_decrypted()
        username = msg.payload.decode()
        self.clients[conn] = username
        self.broadcast(f"{username} entered the chatroom.")
        print(f"{username} connected.")

        try:
            while True:
                msg = conn.recv_decrypted()
                text = msg.payload.decode()
                print(f"{username}: {text}")
                self.broadcast(f"{username}: {text}")
        except ConnectionError:
            print(f"{username} disconnected")
            del self.clients[conn]
            self.broadcast(f"{username} has left the chat.")

    def broadcast(self, text: str) -> None:
        """
        Sends the encrypted message to the whole user's group.

        Args:
            text (str): The message to sent to chat.
        """
        msg = SecureMessage(text.encode())
        for conn, user in list(self.clients.items()):
            try:
                conn.send_encrypted(msg)
            except Exception:
                pass
