from s_aes import aes_encrypt_sequence

def encrypt_saes_ecb(text: str, key: str):
    # Lista para armazenar os blocos de texto (cada bloco tem 2 caracteres)
    blocks = []
    for i in range(len(text) // 2):
        block = text[(i * 2) : ((i + 1) * 2)]
        blocks.append(block)
    # Listas para armazenar os blocos cifrados e suas versões em base64
    cipher_blocks = []
    base64_blocks = []
    count = 1 
    for block in blocks:
        print(f"\nBloco {count}:")
        # Chama a função de cifragem S-AES para cada bloco
        cipher_block = aes_encrypt_sequence(block, key)
        cipher_blocks.append(cipher_block[0])   # Bloco cifrado (hexadecimal)
        base64_blocks.append(cipher_block[2])   # Bloco cifrado (base64)
        count += 1
    # Retorna tupla com listas dos blocos cifrados e em base64
    return (cipher_blocks, base64_blocks)

if __name__ == "__main__":
    # Solicita ao usuário um texto de tamanho par para cifrar
    while True:
        text = input("Digite o texto a ser cifrado: ")
        if len(text) % 2 == 0:
            break
    
    # Solicita a chave de cifragem ao usuário
    key = input("Digite a chave para cifrar o texto: ")
    # Executa a cifragem ECB
    result = encrypt_saes_ecb(text, key)

    # Exibe os blocos cifrados em hexadecimal e base64
    print("Ciphertext: ", ''.join(result[0]))
    print("Base64: ", ''.join(result[1]))