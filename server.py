import asyncio
import random
from utils import xor_decrypt, xor_encrypt
from cryptography.fernet import Fernet
import base64
from math import pi
import hashlib

HOST = 'localhost'
PORT = 9095

# Группа MODP 2048 (RFC 3526)
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

server_secret = random.randint(1, 100)

connected_clients = set()
stop_server_flag = asyncio.Event()


async def handle_echo(reader, writer):
    """
    Обработчик клиента (устойчивый к ошибкам).
    """
    addr = writer.get_extra_info('peername')
    print(f"👤 Подключился: {addr}")

    connected_clients.add(writer)

    data = await reader.readline()
    print(f"🅰️  Получено A: {data.decode().strip()}")
    A = int(data)

    B = pow(g, server_secret, p)

    writer.write((str(B) + '\n').encode())
    await writer.drain()

    K = pow(A, server_secret, p)

    required_length = (K.bit_length() + 7) // 8
    K_bytes = K.to_bytes(required_length, "big")
    K_hash = hashlib.sha256(K_bytes).digest()

    cipher = Fernet(base64.urlsafe_b64encode(K_hash))

    print(f"🔑 Общий ключ K сформирован, значение: {K_hash.hex()}")

    try:
        while True:
            try:
                data = await reader.readline()
            except ConnectionResetError:
                print(f"⚠️ Клиент оборвал соединение: {addr}")
                break

            if not data:
                print(f"👋 Клиент отключился: {addr}")
                break

            print(f"❓ {addr} Сервер принял шифротекст: {data.decode().strip()}")

            print("🔎 Расшифровка...")
            # message = xor_decrypt(data, K).strip()
            message = cipher.decrypt(data).decode().strip()

            print(f"📨 {addr}: {message}")

            try:
                # ciphertext = xor_encrypt(message, K) + b'\n'
                ciphertext = cipher.encrypt(message.encode()) + b'\n'

                print(f"🔐 Сервер сформировал шифротекст: {ciphertext.decode().strip()}")

                writer.write(ciphertext)
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                print(f"⚠️ Ошибка отправки клиенту: {addr}")
                break

    except asyncio.CancelledError:
        # ВАЖНО: не забывать пробрасывать дальше
        print(f"🛑 Задача клиента отменена: {addr}")
        raise

    finally:
        connected_clients.discard(writer)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        print(f"🔌 Соединение закрыто: {addr}")


async def read_server_commands():
    """
    Чтение команд сервера.
    """
    loop = asyncio.get_running_loop()

    while True:
        cmd = await loop.run_in_executor(None, input)

        if cmd.strip() == 'stop':
            print("🛑 Остановка сервера после отключения клиентов")
            stop_server_flag.set()
            return


async def shutdown(server):
    """
    Грейсфул остановка сервера.
    """
    print("⏳ Ожидание отключения клиентов...")

    while connected_clients:
        await asyncio.sleep(1)

    print("🛑 Закрытие сервера...")

    server.close()
    await server.wait_closed()


async def main():
    server = await asyncio.start_server(handle_echo, HOST, PORT)

    print(f"🚀 Сервер запущен на {HOST}:{PORT}")

    async with server:
        tasks = [
            asyncio.create_task(server.serve_forever()),
            asyncio.create_task(read_server_commands())
        ]

        # Ждём команду stop
        await stop_server_flag.wait()

        # Останавливаем сервер
        await shutdown(server)

        # Отменяем все задачи
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)

    print("✅ Сервер полностью остановлен")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Сервер остановлен вручную")
