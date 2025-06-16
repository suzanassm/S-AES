from base64 import b64encode

# --- Funções de Pré-processamento ---

# Converte uma string para sua representação binária de 8 bits por caractere
def string_to_binary(s):
    return ''.join(format(ord(c), '08b') for c in s)

# Converte uma string binária para hexadecimal
def binary_to_hex(b):
    return hex(int(b, 2))[2:]

# Converte uma string binária para base64
def binary_to_base64(b):
    byte_data = int(b, 2).to_bytes((len(b) + 7) // 8, byteorder='big')
    return b64encode(byte_data).decode()

# --- S-Box usada no S-AES (substituição não linear dos nibbles) ---
sbox = {
    '0000': '1001', '0001': '0100', '0010': '1010', '0011': '1011',
    '0100': '1101', '0101': '0001', '0110': '1000', '0111': '0101',
    '1000': '0110', '1001': '0010', '1010': '0000', '1011': '0011',
    '1100': '1100', '1101': '1110', '1110': '1111', '1111': '0111'
}

# Aplica substituição S-Box em uma lista de nibbles (4 bits)
def substitute_nibbles(state):
    return [sbox[nib] for nib in state]

# Aplica substituição S-Box em um byte (8 bits = 2 nibbles)
def nibble_sub(byte):
    return sbox[byte[:4]] + sbox[byte[4:]]

# --- ShiftRows (inversão dos nibbles da segunda linha da matriz de estado) ---
def shift_rows(state_matrix):
    return [
        [state_matrix[0][0], state_matrix[0][1]],  # primeira linha inalterada
        [state_matrix[1][1], state_matrix[1][0]]   # segunda linha trocada
    ]

# --- MixColumns (multiplicações no corpo finito GF(2^4)) ---

# Tabela de multiplicação no GF(2^4) para elementos 1 e 4
gf16_mul = {
    (1, i): i for i in range(16)  # multiplicação por 1 é identidade
}
# Multiplicações por 4 pré-calculadas no corpo finito
gf16_mul.update({
    (4, 0): 0, (4, 1): 4, (4, 2): 8, (4, 3): 12,
    (4, 4): 3, (4, 5): 7, (4, 6): 11, (4, 7): 15,
    (4, 8): 6, (4, 9): 2, (4,10): 14, (4,11): 10,
    (4,12): 5, (4,13): 1, (4,14): 13, (4,15): 9
})

# Executa MixColumns na matriz de estado (multiplicação matricial no GF(2^4))
def mix_columns(state_matrix):

    result = [['0', '0'], ['0', '0']]
    for c in range(2):

        a = int(state_matrix[0][c], 2)
        b = int(state_matrix[1][c], 2)
        # Realiza multiplicações e XORs conforme matriz padrão do S-AES
        r0 = gf16_mul[(1, a)] ^ gf16_mul[(4, b)]
        r1 = gf16_mul[(4, a)] ^ gf16_mul[(1, b)]
        # Converte o resultado para binário de 4 bits
        result[0][c] = format(r0, '04b')
        result[1][c] = format(r1, '04b')
    return result

# --- AddRoundKey (XOR entre matriz de estado e a chave de rodada) ---
def add_round_key(state_matrix, round_key_matrix):
    return [
        [format(int(state_matrix[i][j], 2) ^ int(round_key_matrix[i][j], 2), '04b') for j in range(2)]
        for i in range(2)
    ]

# --- Expansão de chave de 16 bits para 6 palavras de 8 bits ---
def key_expansion(key16):
    w0 = key16[:8]
    w1 = key16[8:]

    # Constantes de rodada (Rcon)
    Rcon1 = '10000000'  # R1 = 0x80
    Rcon2 = '00110000'  # R2 = 0x30

    # XOR de duas strings binárias
    def xor(a, b):
        return format(int(a, 2) ^ int(b, 2), '08b')

    # Rotaciona nibbles de um byte (ex: ABCD -> CDAB)
    def rot_nib(b):
        return b[4:] + b[:4]

    # Substitui cada nibble do byte usando a S-Box
    def sub_nib(b):
        return sbox[b[:4]] + sbox[b[4:]]

    # Gera palavras w2 a w5 com operações XOR, rot_nib, sub_nib e Rcon
    w2 = xor(w0, xor(Rcon1, sub_nib(rot_nib(w1))))
    w3 = xor(w2, w1)
    w4 = xor(w2, xor(Rcon2, sub_nib(rot_nib(w3))))
    w5 = xor(w4, w3)

    return [w0, w1, w2, w3, w4, w5]

# --- Função principal de cifra de um bloco de 16 bits ---
def cipher_block(plaintext_bin, round_keys):
    # Divide texto binário em matriz 2x2 de nibbles (4 bits)
    state = [[plaintext_bin[0:4], plaintext_bin[4:8]], [plaintext_bin[8:12], plaintext_bin[12:16]]]

    # Rodada 0: Adiciona chave inicial (w0 e w1)
    key0 = [[round_keys[0][:4], round_keys[0][4:]], [round_keys[1][:4], round_keys[1][4:]]]
    state = add_round_key(state, key0)

    # Rodada 1: Substituição -> ShiftRows -> MixColumns -> AddRoundKey
    state = substitute_nibbles([nib for row in state for nib in row])
    state = [[state[0], state[1]], [state[2], state[3]]]
    state = shift_rows(state)
    state = mix_columns(state)
    key1 = [[round_keys[2][:4], round_keys[2][4:]], [round_keys[3][:4], round_keys[3][4:]]]
    state = add_round_key(state, key1)

    # Rodada 2: Substituição -> ShiftRows -> AddRoundKey (sem MixColumns)
    state = substitute_nibbles([nib for row in state for nib in row])
    state = [[state[0], state[1]], [state[2], state[3]]]
    state = shift_rows(state)
    key2 = [[round_keys[4][:4], round_keys[4][4:]], [round_keys[5][:4], round_keys[5][4:]]]
    state = add_round_key(state, key2)

    # Retorna o texto cifrado como string binária
    return ''.join([nib for row in state for nib in row])


# Função principal
def aes_encrypt_sequence(plaintext, key):
    
    # 1. Converter texto para binário

    plaintext_bin = string_to_binary(plaintext[:2])
    print(f'Texto original: "{plaintext}"')
    print("Texto binário:", plaintext_bin)


    # 2. Gerar round keys a partir da chave
    round_keys = key_expansion(key)


    # 3. Executa cifragem com 3 rodadas do S-AES
    ciphertext_bin = cipher_block(plaintext_bin, round_keys)

    # 4. Exibe resultado em binário, hexadecimal e base64
    print("Cifra (bin):", ciphertext_bin)
    print("Cifra (hex):", binary_to_hex(ciphertext_bin))
    print("Cifra (b64):", binary_to_base64(ciphertext_bin))
    print()
    return (ciphertext_bin, binary_to_hex(ciphertext_bin), binary_to_base64(ciphertext_bin))

# --- Executa a função principal se for o script principal ---
if __name__ == "__main__":
    aes_encrypt_sequence("ok", "1010110010101100")