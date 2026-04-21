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

                    required_length = (K.bit_length() + 7) // 8
                    K_bytes = K.to_bytes(required_length, "big")
                    K_hash = hashlib.sha256(K_bytes).digest()

                    cipher = Fernet(base64.urlsafe_b64encode(K_hash))
                    
                    print(f"🔑 Общий ключ K сформирован, значение: {K_hash.hex()}")

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
                    print(f"a: {client_secret},\nA: {A},\nB: {B},\nK: {K_hash.hex()}")
                    continue

                try:
                    # writer.write(xor_encrypt(message, K) + b'\n')
                    writer.write(cipher.encrypt(message.encode()) + b'\n')
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

                # print(f"📩 Ответ: {xor_decrypt(data, K).strip()}")
                print(f"📩 Ответ: {cipher.decrypt(data).decode().strip()}")

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
