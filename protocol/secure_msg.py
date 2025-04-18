"""
Secure Message protocol
"""

import hashlib


class SecureMessage:
    """
    Message wrapper to serializes the message.
    """

    payload: bytes
    digest: bytes

    def __init__(self, payload: bytes):
        self.payload = payload
        self.digest = hashlib.sha256(payload).digest()

    def serialize(self) -> bytes:
        """
        Serializes the message.

        Returns:
            bytes: The serialized message.
        """
        dlen = len(self.digest).to_bytes(4, "big")
        return dlen + self.digest + self.payload

    @classmethod
    def deserialize(cls, raw: bytes) -> "SecureMessage":
        """
        Deserealize the message and check the message integrity.

        Args:
            raw (bytes): The raw message bytes.

        Returns:
            SecureMessage: object encrypted with RSA + OAEP.
        """
        dlen = int.from_bytes(raw[:4], "big")
        digest = raw[4 : 4 + dlen]
        payload = raw[4 + dlen :]
        if hashlib.sha256(payload).digest() != digest:
            raise ValueError("Integrity test not passed")
        msg = cls(payload)
        msg.digest = digest
        return msg
