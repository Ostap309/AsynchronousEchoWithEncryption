import socket
import random

HOST = '127.0.0.1'
PORT = 5000

# параметры (для учебы маленькие)
p = 23
g = 5

server_secret = random.randint(1, 100)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print("[SERVER] Waiting for connection...")
    conn, addr = s.accept()

    with conn:
        print(f"[SERVER] Connected: {addr}")

        # получаем A от клиента
        data = conn.recv(1024).decode()
        A = int(data)

        # считаем B
        B = pow(g, server_secret, p)

        # отправляем B
        conn.send(str(B).encode())

        # вычисляем общий секрет
        K = pow(A, server_secret, p)
        print(f"[SERVER] Shared key: {K}")
