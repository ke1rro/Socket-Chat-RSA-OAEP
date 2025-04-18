import sys

from network.client import ChatClient
from network.server import ChatServer

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "client":
        ChatServer().start()
    else:
        _, _, name = sys.argv
        ChatClient(username=name).connect()
