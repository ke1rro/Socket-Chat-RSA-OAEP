"""
Module for Chat Client
"""

import socket
import threading

from cryptography.rsa import RSAKeyPair
from protocol.secure_msg import SecureMessage

from .connection import Connection


class ChatClient:
    """
    Chat client
    """

    username: str
    host: str
    port: int

    def __init__(self, username: str, host="127.0.0.1", port=10000):
        self.addr = (host, port)
        self.rsa = RSAKeyPair()
        self.conn: Connection | None = None
        self.username = username

    def connect(self):
        """
        Connection handler
        """
        sock = socket.socket()
        sock.connect(self.addr)
        n, e = self.rsa.public_key
        sock.sendall(f"{n},{e}".encode())
        raw = sock.recv(4096).decode()
        sn, se = map(int, raw.split(","))
        self.conn = Connection(sock, rsa=self.rsa, pub_key=(sn, se))
        self.conn.send_encrypted(SecureMessage(self.username.encode()))

        read_thread = threading.Thread(target=self.read_loop, daemon=True)
        write_thread = threading.Thread(target=self.write_loop, daemon=True)

        read_thread.start()
        write_thread.start()

        read_thread.join()

    def read_loop(self):
        """
        Reads the message from other clients broadcated by server
        """
        while True:
            try:
                msg = self.conn.recv_decrypted()
                print(msg.payload.decode())
            except (KeyboardInterrupt, OSError):
                self.conn.close()
                print("Disconnected from the chatroom")
                break

    def write_loop(self) -> None:
        """
        Writes the messages user client broadcasted by server.
        """

        while True:
            text = input("> ")
            if text == "q":
                self.conn.close()
            else:
                msg = SecureMessage(text.encode())
            try:
                self.conn.send_encrypted(msg)
            except Exception as ex:
                break
