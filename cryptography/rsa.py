"""
Module to handle RSA key
"""

import hashlib
import secrets

from miller_rabin import MillerRabin


class RSAKeyPair:
    """
    Module for exchanging key pairs:
    Private and Public keys


    Attributes:
        p: Prime number genereted by Miller-Rabin test
        q: Prime number genereted by Miller-Rabin test
        n: The RSA modulus
        exponent: Public exponents 65537 used as standart value
        d: Private exponent
    """

    bits: int

    def __init__(self, bits: int = 2048):
        self.p, self.q = self.__gen_prime_factors(bits)
        self.n = self.p * self.q
        self.exponent = 65537

        if isinstance(self.p, int):
            phi = (self.p - 1) * (self.q - 1)
            # To prevent integer overflow
            self.d = pow(self.exponent, -1, phi)

    def __gen_prime(self, bits: int) -> int:
        """
        Generates the prime number using Miller-Rabin prime test

        Args:
            bits (int): The length of the number to generate

        Returns:
            int: The prime number of the given bits
        """
        while True:
            candidate = self.__gen_candidate(bits)
            if MillerRabin.isPrime(candidate):
                return candidate

    @staticmethod
    def __gen_candidate(bits: int) -> int:
        """
        Generates a random bit number
        Ensures it is fixed length and not even.

        Args:
            bits (int): The length of the number to generate

        Returns:
            int: The odd number of the fixed length
        """
        return (1 << (bits - 1)) | secrets.randbits(bits - 1) | 1

    def __gen_prime_factors(
        self, bits: int, min_factor_delta=256, attempts=100000
    ) -> tuple[int, int]:
        """_summary_

        Args:
            bits (int): _description_
            min_factor_delta (int, optional): _description_. Defaults to 256.
            attempts (int, optional): _description_. Defaults to 100000.

        Returns:
            tuple[int, int]: _description_
        """
        for _ in range(attempts):
            p = self.__gen_prime(bits // 2)
            q = self.__gen_prime(bits // 2)
            if p == q:
                continue

            if abs(p - q).bit_length() >= min_factor_delta:
                return p, q
        return f"Couldn't generate a prime factors in {attempts} attempts"

    @property
    def public_key(self) -> tuple[int, int]:
        """
        Provides the public key for the client

        Returns:
            tuple[int, int]: The module and exponent
        """
        return self.n, self.exponent

    def get_block_length(self, n) -> int:
        """
        Returns the max message length that can be encrypted with OAEP
        M is the message to be padded, with length mLen (at most mLen=k−2⋅hLen−2 bytes)
        Args:
            n (int): RSA modulus

        Returns:
            int: The max message length in bytes
        """
        hash_len = hashlib.sha256().digest_size
        modul_len = (n.bit_length() + 7) // 8
        return modul_len - 2 * hash_len - 2

    @staticmethod
    def mgf1(seed: bytes, length: int, hash_func=hashlib.sha1) -> bytes:
        """Mask generation function took from Wiki https://en.wikipedia.org/wiki/Mask_generation_function"""

        hLen = hash_func().digest_size
        # https://www.ietf.org/rfc/rfc2437.txt
        # 1. If l > 2^32(hLen), output "mask too long" and stop.
        if length > (hLen << 32):
            raise ValueError("mask too long")
        # 2. Let T be the empty octet string.
        T = b""
        # 3. For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
        # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
        #       but it's easier to check if we have reached the desired length.
        counter = 0
        while len(T) < length:
            # a. Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
            C = int.to_bytes(counter, 4, "big")
            # b. Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
            T += hash_func(seed + C).digest()
            counter += 1
        # 4. Output the leading l octets of T as the octet string mask.
        return T[:length]

    def oaep_pad(self, message: bytes, label: bytes = b"") -> bytes:
        """
        Puts the mask on the plain (raw) message

        Args:
            message (bytes): The message to apply padding
            label (bytes, optional): Optional label. Defaults to b"".

        Returns:
            bytes: OAEP padded message
        """
        hash_len = hashlib.sha256().digest_size
        modulus_len = (self.n.bit_length() + 7) // 8

        max_msg_len = self.get_block_length(self.n)
        if len(message) > max_msg_len:
            raise ValueError("Message to long")

        lhash = hashlib.sha256(label).digest()
        ps = b"\x00" * (modulus_len - len(message) - 2 * hash_len - 2)
        db = lhash + ps + b"\x01" + message

        # Generate random seed r
        seed = secrets.token_bytes(hash_len)

        # Apply MFG1 to get fast part P_1 (P_1 = M ⊕ G(r))
        db_mask = self.mgf1(seed, len(db), hashlib.sha256)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        # Apply MFG1 to get the second part P_2 (P_2 = r ⊕ H(P_1))
        seed_mask = self.mgf1(masked_db, hash_len, hashlib.sha256)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

        # Concatenate everyting (EM = 0x00 || maskedSeed || maskedDB)
        return b"\x00" + masked_seed + masked_db

    def oaep_unpad(self, padded_data: bytes, label: bytes = b"") -> bytes:
        """
        Removes the OAEP padding to get the original message

        Args:
            padded_data (bytes): OAEP padded data
            label (bytes, optional): Optional label. Defaults to b"".

        Returns:
            bytes: Original message
        """
        hash_len = hashlib.sha256().digest_size

        if len(padded_data) < 2 * hash_len + 2:
            raise ValueError("Invalid padding: data too short")

        if padded_data[0] != 0:
            raise ValueError("Invalid padding: first byte not zero")

        # Split parts
        masked_seed = padded_data[1:hash_len+1]
        masked_db = padded_data[hash_len+1:]

        # Recover r using H(maskedDB)
        seed_mask = self.mgf1(masked_db, hash_len, hashlib.sha256)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

        # Recover DB using G(r)
        db_mask = self.mgf1(seed, len(masked_db), hashlib.sha256)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        # Verify label hash and extract message
        lhash = hashlib.sha256(label).digest()

        # Check if label hash matches
        if not db.startswith(lhash):
            raise ValueError("Invalid padding: label hash mismatch")

        # Find the 0x01 separator
        separator_idx = hash_len
        while separator_idx < len(db):
            if db[separator_idx] == 1:
                break
            if db[separator_idx] != 0:
                raise ValueError("Invalid padding format")
            separator_idx += 1

        if separator_idx >= len(db) - 1:
            raise ValueError("Message separator not found")

        # Return the message after the separator
        return db[separator_idx + 1:]

    def encrypt(self, data: bytes, pubkey: tuple[int, int] = None) -> bytes:
        """
        Encrypt data using RSA-OAEP

        Args:
            data (bytes): Data to encrypt
            pubkey (tuple[int, int], optional): External public key (n, e). Defaults to None.

        Returns:
            bytes: Encrypted data
        """
        n, e = pubkey if pubkey else (self.n, self.exponent)
        block_size = self.get_block_length(n)
        encrypted = []

        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            padded = self.oaep_pad(chunk)
            chunk_int = int.from_bytes(padded, 'big')
            cipher_int = pow(chunk_int, e, n)
            cipher_block = cipher_int.to_bytes((n.bit_length() + 7) // 8, 'big')
            encrypted.append(cipher_block)

        return b''.join(encrypted)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using RSA-OAEP

        Args:
            data (bytes): Encrypted data

        Returns:
            bytes: Decrypted data
        """
        block_size = (self.n.bit_length() + 7) // 8
        decrypted = []

        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            chunk_int = int.from_bytes(chunk, 'big')
            plain_int = pow(chunk_int, self.d, self.n)
            plain_block = plain_int.to_bytes(block_size, 'big')
            decrypted.append(self.oaep_unpad(plain_block))

        return b''.join(decrypted)