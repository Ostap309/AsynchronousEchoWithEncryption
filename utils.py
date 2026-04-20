def xor_encrypt(text: str, key: int) -> bytes:
    return bytes([c ^ key for c in text.encode()])


def xor_decrypt(data: bytes, key: int) -> str:
    return ''.join(chr(b ^ key) for b in data)
