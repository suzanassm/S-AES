from s_aes import aes_encrypt_sequence

def encrypt_saes_ecb(text: str, key: str):
    blocks = []
    for i in range(len(text) // 2):
        block = text[(i * 2) : ((i + 1) * 2)]
        blocks.append(block)
    cipher_blocks = []
    for block in blocks:
        cipher_block = aes_encrypt_sequence(block, key)
        cipher_blocks.append(cipher_block)

    return cipher_blocks

if __name__ == "__main__":
    while True:
        text = input("Digite o texto a ser cifrado:")
        if len(text) % 2 == 0:
            break
    
    key = input("Digite a chave para cifrar o texto")
    ciphertext = encrypt_saes_ecb(text, key)
    print(ciphertext)

    
