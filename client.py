import socket
import random

HOST = '127.0.0.1'
PORT = 5000

p = 23
g = 5

client_secret = random.randint(1, 100)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # считаем A
    A = pow(g, client_secret, p)

    # отправляем A
    s.send(str(A).encode())

    # получаем B
    data = s.recv(1024).decode()
    B = int(data)

    # общий ключ
    K = pow(B, client_secret, p)

    print(f"[CLIENT] Shared key: {K}")
