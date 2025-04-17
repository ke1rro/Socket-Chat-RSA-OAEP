"""Miller-Rabin test"""

from random import randint


def miller_rabin(n, k=40):
    """Miller-Rabin primality test"""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        x = pow(randint(2, n - 2), d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True
