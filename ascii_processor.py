from sdes_core import encrypt, decrypt

def ascii_to_binary(s):
    binary = []
    for char in s:
        binary.append(format(ord(char), '08b'))
    return binary

def binary_to_ascii(binary_list):
    ascii_str = ""
    for binary in binary_list:
        if len(binary) != 8:
            raise ValueError("每个二进制分组必须是8位")
        ascii_str += chr(int(binary, 2))
    return ascii_str

def encrypt_ascii(text, key):
    binary_blocks = ascii_to_binary(text)
    encrypted_blocks = [encrypt(block, key) for block in binary_blocks]
    return binary_to_ascii(encrypted_blocks)

def decrypt_ascii(text, key):
    binary_blocks = ascii_to_binary(text)
    decrypted_blocks = [decrypt(block, key) for block in binary_blocks]
    return binary_to_ascii(decrypted_blocks)
    