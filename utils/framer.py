"""
Additional message processing layer
"""

import socket
import struct


class FrameLayer:
    """
    Class to handle headers logic for the message
    help to compute the exact size, so you
    """

    HEADER_FMT = "!I"
    HEADER_SIZE = struct.calcsize(HEADER_FMT)

    @staticmethod
    def pack(payload: bytes) -> bytes:
        """
        Redifine the payload by adding a 4-byte prefix (message header).

        Args:
            payload (bytes): The message data to frame

        Returns:
            bytes: Framed message consisting of 4-byte length header and payload
        """
        return struct.pack(FrameLayer.HEADER_FMT, len(payload)) + payload

    @staticmethod
    def unpack(sock: socket.socket) -> bytes:
        """
        Read a framed message from the socket by frist reading the 4-byte header,
        which help to determine dynamicly the payload length.

        Args:
            sock (socket.socket): A connected socket (user) to read from.

        Returns:
            bytes: The raw payload
        """

        header = sock.recv(FrameLayer.HEADER_SIZE)
        if not header:
            raise ConnectionError("Connection failed.")

        length = struct(FrameLayer.HEADER_FMT, header)[0]
        buf = b""
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                raise ConnectionError("Connection not handled")
            buf += chunk
        return buf
