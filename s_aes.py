from base64 import b64encode

# Pré-processamento
def string_to_binary(s):
    return ''.join(format(ord(c), '08b') for c in s)

def binary_to_hex(b):
    return hex(int(b, 2))[2:]

def binary_to_base64(b):
    byte_data = int(b, 2).to_bytes((len(b) + 7) // 8, byteorder='big')
    return b64encode(byte_data).decode()

# S-Box
sbox = {
    '0000': '1001', '0001': '0100', '0010': '1010', '0011': '1011',
    '0100': '1101', '0101': '0001', '0110': '1000', '0111': '0101',
    '1000': '0110', '1001': '0010', '1010': '0000', '1011': '0011',
    '1100': '1100', '1101': '1110', '1110': '1111', '1111': '0111'
}

# Subs. de nibbles
def substitute_nibbles(state):
    return [sbox[nib] for nib in state]

def nibble_sub(byte):
    return sbox[byte[:4]] + sbox[byte[4:]]

# Shift Rows
def shift_rows(state_matrix):
    return [
        [state_matrix[0][0], state_matrix[0][1]],
        [state_matrix[1][1], state_matrix[1][0]]
    ]

#  Mix Columns
gf16_mul = {
    (1, i): i for i in range(16)
}
gf16_mul.update({
    (4, 1): 4, (4, 2): 8, (4, 3): 12, (4, 4): 3,
    (4, 5): 7, (4, 6): 11, (4, 7): 15, (4, 8): 6,
    (4, 9): 2, (4, 10): 14, (4, 11): 10, (4, 12): 5,
    (4, 13): 1, (4, 14): 13, (4, 15): 9, (4, 0): 0
})

def mix_columns(state_matrix):
    result = [['0', '0'], ['0', '0']]
    for c in range(2):
        a = int(state_matrix[0][c], 2)
        b = int(state_matrix[1][c], 2)
        r0 = gf16_mul[(1, a)] ^ gf16_mul[(4, b)]
        r1 = gf16_mul[(4, a)] ^ gf16_mul[(1, b)]
        result[0][c] = format(r0, '04b')
        result[1][c] = format(r1, '04b')
    return result

#  Add Round Key
def add_round_key(state_matrix, round_key_matrix):
    return [
        [format(int(state_matrix[i][j], 2) ^ int(round_key_matrix[i][j], 2), '04b') for j in range(2)]
        for i in range(2)
    ]

# Key Expansion (expande chave de 16 bits para 3 rodadas de 8 bits cada) ---
def key_expansion(key16):
    # Divide a chave em w0 e w1
    w0 = key16[:8]
    w1 = key16[8:]

    # Constantes (Rcon)
    Rcon1 = '10000000'  # 0x80
    Rcon2 = '00110000'  # 0x30

    def xor(a, b):
        return format(int(a, 2) ^ int(b, 2), '08b')

    def rot_nib(b):
        return b[4:] + b[:4]

    def sub_nib(b):
        return sbox[b[:4]] + sbox[b[4:]]

    w2 = xor(w0, xor(Rcon1, sub_nib(rot_nib(w1))))
    w3 = xor(w2, w1)
    w4 = xor(w2, xor(Rcon2, sub_nib(rot_nib(w3))))
    w5 = xor(w4, w3)

    return [w0, w1, w2, w3, w4, w5]

# Cifra de um bloco de 16 bits
def cipher_block(plaintext_bin, round_keys):
    # Etapa 1: Dividir bloco 16 bits em 2x2 matriz de nibbles
    state = [[plaintext_bin[0:4], plaintext_bin[4:8]], [plaintext_bin[8:12], plaintext_bin[12:16]]]

    # Round 0: AddRoundKey com w0 e w1
    key0 = [[round_keys[0][:4], round_keys[0][4:]], [round_keys[1][:4], round_keys[1][4:]]]
    state = add_round_key(state, key0)

    # Round 1
    state = substitute_nibbles([nib for row in state for nib in row])
    state = [[state[0], state[1]], [state[2], state[3]]]
    state = shift_rows(state)
    state = mix_columns(state)
    key1 = [[round_keys[2][:4], round_keys[2][4:]], [round_keys[3][:4], round_keys[3][4:]]]
    state = add_round_key(state, key1)

    # Round 2
    state = substitute_nibbles([nib for row in state for nib in row])
    state = [[state[0], state[1]], [state[2], state[3]]]
    state = shift_rows(state)
    key2 = [[round_keys[4][:4], round_keys[4][4:]], [round_keys[5][:4], round_keys[5][4:]]]
    state = add_round_key(state, key2)

    return ''.join([nib for row in state for nib in row])

# Função principal
def aes_encrypt_sequence(plaintext, key):
    
    # 1. Converter texto para binário
    plaintext_bin = string_to_binary(plaintext[:2])
    print("Texto original:", plaintext)
    print("Texto binário:", plaintext_bin)

    # 2. Gerar round keys a partir da chave
    round_keys = key_expansion(key)

    # 3. Cifrar
    ciphertext_bin = cipher_block(plaintext_bin, round_keys)

    # 4. Exibir saída
    print("Cifra (bin):", ciphertext_bin)
    return ciphertext_bin
    # print("Cifra (hex):", binary_to_hex(ciphertext_bin))
    # print("Cifra (b64):", binary_to_base64(ciphertext_bin))

# --- Executa ---
if __name__ == "__main__":
    aes_encrypt_sequence("ok", "1010010111110000")
