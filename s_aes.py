from base64 import b64encode

def string_to_binary(s):
    return ''.join(format(ord(c), '08b') for c in s)

def binary_to_hex(b):
    return hex(int(b, 2))[2:]

def binary_to_base64(b):
    byte_data = int(b, 2).to_bytes((len(b) + 7) // 8, byteorder='big')
    return b64encode(byte_data).decode()
