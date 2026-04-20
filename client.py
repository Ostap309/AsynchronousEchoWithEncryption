import asyncio
import random
from utils import xor_decrypt, xor_encrypt

HOST = 'localhost'
PORT = 9095

p = 23
g = 5

async def tcp_echo_client():
    """
    Клиент с авто-переподключением и нормальной обработкой ошибок.
    """

    loop = asyncio.get_running_loop()

    while True:  # Главный цикл жизни клиента (переподключение)
        reader = None
        writer = None

        try:
            # --- ПОДКЛЮЧЕНИЕ ---
            while True:
                try:
                    reader, writer = await asyncio.open_connection(HOST, PORT)
                    print(f"✅ Подключено к серверу {HOST}:{PORT}")

                    client_secret = random.randint(1, 100)
                    A = pow(g, client_secret, p)

                    writer.write((str(A) + '\n').encode())
                    await writer.drain()

                    data = await reader.readline()
                    print(f"🅱️  Получено B: {data.decode().strip()}")
                    B = int(data)

                    K = pow(B, client_secret, p)
                    print(f"🔑 Общий ключ K сформирован, значение: {K}")

                    break
                except ConnectionRefusedError:
                    print("⛔ Сервер недоступен. Повтор через 3 сек...")
                    await asyncio.sleep(3)

            # --- РАБОТА С СЕРВЕРОМ ---
            while True:
                message = await loop.run_in_executor(
                    None,
                    input,
                    "Введите сообщение (exit для выхода): "
                )

                if message.lower() == 'exit':
                    print("👋 Выход из клиента")
                    return  # полностью завершаем клиент
                elif message.lower() == 'keysinfo':
                    print(f"a: {client_secret},\nA: {A},\nB: {B},\nK: {K}")
                    continue

                try:
                    writer.write(xor_encrypt(message, K) + b'\n')
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError):
                    print("⚠️ Соединение потеряно при отправке")
                    break  # переподключение

                try:
                    data = await reader.readline()
                except ConnectionResetError:
                    print("⚠️ Сервер разорвал соединение")
                    break

                if not data:
                    print("⚠️ Сервер закрыл соединение")
                    break

                print(f"📩 Ответ: {xor_decrypt(data, K).strip()}")

        except KeyboardInterrupt:
            print("\n🛑 Клиент остановлен пользователем")
            break

        except Exception as e:
            # Ловим ВСЁ, чтобы клиент не падал
            print(f"❌ Неожиданная ошибка: {e}")

        finally:
            # --- ГАРАНТИРОВАННОЕ ЗАКРЫТИЕ ---
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            print("🔄 Переподключение...")


if __name__ == '__main__':
    asyncio.run(tcp_echo_client())
