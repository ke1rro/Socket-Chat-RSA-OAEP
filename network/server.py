"""
Chat server module
"""

import socket
import threading

from cryptography.rsa import RSAKeyPair
from protocol.secure_msg import SecureMessage

from .connection import Connection


class ChatServer:
    """
    Class the handles thread safely the connected sockets
    """

    hos: str
    address: int

    def __init__(self, host: str = "127.0.0.1", address: int = 10000):
        self.address = (host, address)
        self.rsa: RSAKeyPair = RSAKeyPair()
        self.clients: dict[Connection, str] = {}
        self.running = True
        self.sessions = []

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

        while self.running:
            try:
                client_sock, _ = sock.accept()
                conn = Connection(client_sock)
                thread = threading.Thread(
                    target=self.handle_connection, args=(conn,), daemon=True
                )
                self.sessions.append(thread)
                thread.start()
            except (KeyboardInterrupt, OSError):
                self.running = False
                self.soft_shutdown()
        sock.close()

    def handle_handshake(self, conn: Connection) -> None:
        """
        Exchanges the public key with the client.

        Args:
            conn (Connection): The client connection object.
        """
        raw = conn.sock.recv(4096).decode()
        n, e = map(int, raw.split(","))
        conn.pub_key = (n, e)
        sn, se = self.rsa.public_key
        conn.sock.sendall(f"{sn},{se}".encode())
        conn.rsa = self.rsa

    def handle_connection(self, conn: Connection) -> None:
        """
        Handles each user (socket connection) on separeted thread
        and introducing user to whole chatroom.

        Args:
            conn (Connection): The new user's connection object
        """
        username = None
        try:
            self.handle_handshake(conn)

            msg = conn.recv_decrypted()
            username = msg.payload.decode()
            self.clients[conn] = username
            self.broadcast(f"{username} entered the chatroom.")
            print(f"{username} connected.")

            while self.running:
                try:
                    conn.sock.settimeout(1.0)
                    msg = conn.recv_decrypted()
                    text = msg.payload.decode()
                    print(f"{username}: {text}")
                    self.broadcast(f"{username}: {text}")
                except socket.timeout:
                    continue
                except ConnectionError:
                    break
                except Exception as e:
                    print(f"Error handling message: {e}")
                    break

        except Exception as e:
            pass

        finally:
            if username and conn in self.clients:
                print(f"{username} disconnected")
                self.broadcast(f"{username} has left the chat.")
                del self.clients[conn]

            try:
                conn.close()
            except:
                pass

    def broadcast(self, text: str) -> None:
        """
        Sends the encrypted message to the whole user's group.

        Args:
            text (str): The message to sent to chat.
        """
        msg = SecureMessage(text.encode())
        for conn, _ in list(self.clients.items()):
            try:
                conn.send_encrypted(msg)
            except Exception:
                pass

    def soft_shutdown(self):
        """
        Closes all active sessions
        """

        for conn in self.clients.keys():
            try:
                conn.close()
            except:
                pass

        for thread in self.sessions:
            try:
                thread.join()
            except:
                pass

        print("All sessions closed")
