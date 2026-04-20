import asyncio
import random
from utils import xor_decrypt, xor_encrypt

HOST = 'localhost'
PORT = 9095

p = 23
g = 5

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
    print(f"🔑 Общий ключ K сформирован, значение: {K}")

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
            message = xor_decrypt(data, K).strip()

            print(f"📨 {addr}: {message}")

            try:
                ciphertext = xor_encrypt(message, K) + b'\n'

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
