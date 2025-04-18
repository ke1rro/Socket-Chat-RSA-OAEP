"""
Module provides User Connection class
"""

import socket

from cryptography.rsa import RSAKeyPair
from protocol.secure_msg import SecureMessage
from utils.framer import FrameLayer


class Connection:
    """
    Connection class that allows sessions to communicate
    """

    sock: socket.socket
    rsa: RSAKeyPair
    pub_key: tuple[int, int]

    def __init__(
        self,
        sock: socket.socket,
        rsa: RSAKeyPair = None,
        pub_key: tuple[int, int] = None,
    ):
        self.rsa = rsa
        self.pub_key = pub_key
        self.sock = sock

    def send_raw(self, data: bytes) -> None:
        """
        Send raw bytes with Header

        Args:
            data (bytes): The data to send
        """
        frame = FrameLayer.pack(data)
        self.sock.sendall(frame)

    def recv_raw(self) -> bytes:
        """
        Receive the message Framed and unpack the header

        Args:
            sefl (_type_): _description_

        Returns:
            bytes: _description_
        """
        return FrameLayer.unpack(self.sock)

    def send_encrypted(self, msg: SecureMessage) -> None:
        """
        Sends the encypted RSA message

        Args:
            msg (SecureMessage): The message to encrypt
        """
        serialized = msg.serialize()
        cipher = self.rsa.encrypt(serialized, self.pub_key)
        self.send_raw(cipher)

    def recv_decrypted(self) -> "SecureMessage":
        """
        Decrypts the message

        Returns:
            SecureMessage: encrypted message to decrypt
        """
        cipher = self.recv_raw()
        plaintext = self.rsa.decrypt(cipher)
        return SecureMessage.deserialize(plaintext)

    def close(self) -> None:
        """
        Helper function to close connection
        """
        self.sock.close()
