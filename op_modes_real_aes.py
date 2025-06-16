# Importa as bibliotecas necessárias para criptografia, padding, geração de bytes aleatórios, codificação base64 e medição de tempo
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64
import time

NUM_LOOPS = 1000

# Gera uma chave aleatória de 16 bytes para o AES (128 bits)
key = get_random_bytes(16) # Chave AES de 16 bytes
# Gera um vetor de inicialização (IV) aleatório de 16 bytes
iv = get_random_bytes(16) # Vetor de inicialização
# Define o texto plano a ser cifrado
plaintext = b"Exemplo de plaintext para cifragem em diferentes modos."

# Função para exibir os resultados de cada modo de operação
# modo: nome do modo de operação
# ciphertext: texto cifrado
# tempo: tempo médio de execução

def results (modo: str, ciphertext, tempo: float):
    print(f"Modo: {modo}")
    print(f"Tempo medio de execução: {tempo:.8f} segundos")
    print(f"Texto cifrado (Base64): {base64.b64encode(ciphertext).decode()}\n")

# Modo ECB (Electronic Codebook)
media_ecb = 0
start = time.perf_counter() # Inicia a contagem do tempo
ciphertext_ecb = b''  # Garantir que a variável está definida
for _ in range(NUM_LOOPS):
    # Cria o objeto de cifra AES no modo ECB
    cipher = AES.new(key, AES.MODE_ECB)
    # Aplica padding ao plaintext e cifra
    ciphertext_ecb = cipher.encrypt(pad(plaintext, AES.block_size))
end = time.perf_counter() # Finaliza a contagem do tempo
media_ecb += end - start
# Exibe os resultados do modo ECB
results("ECB", ciphertext_ecb, media_ecb/NUM_LOOPS)


# Modo CBC (Cipher Block Chaining)
media_cbc = 0
start = time.perf_counter()
ciphertext_cbc = b''  # Garantir que a variável está definida
for _ in range(NUM_LOOPS):
    # Cria o objeto de cifra AES no modo CBC com IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Aplica padding ao plaintext e cifra
    ciphertext_cbc = cipher.encrypt(pad(plaintext, AES.block_size))
end = time.perf_counter()
media_cbc += end - start
# Exibe os resultados do modo CBC
results("CBC", ciphertext_cbc, media_cbc/NUM_LOOPS)

# Modo CFB (Cipher Feedback)
media_cfb = 0
start = time.perf_counter()
ciphertext_cfb = b''  # Garantir que a variável está definida

for _ in range(NUM_LOOPS):
    # Cria o objeto de cifra AES no modo CFB com IV
    cipher = AES.new(key, AES.MODE_CFB, iv)
    # Cifra o plaintext
    ciphertext_cfb = cipher.encrypt(plaintext)
end = time.perf_counter()
media_cfb += end - start
# Exibe os resultados do modo CFB
results("CFB", ciphertext_cfb, media_cfb/NUM_LOOPS)

# Modo OFB (Output Feedback)
media_ofb = 0
start = time.perf_counter()
ciphertext_ofb = b''  # Garantir que a variável está definida

for _ in range(NUM_LOOPS):
    # Cria o objeto de cifra AES no modo OFB com IV
    cipher = AES.new(key, AES.MODE_OFB, iv)
    # Cria o texto cifrado
    ciphertext_ofb = cipher.encrypt(plaintext)
end = time.perf_counter()
media_ofb += end - start
# Exibe os resultados do modo OFB
results("OFB", ciphertext_ofb, media_ofb/NUM_LOOPS)


# Modo CTR (Counter)
media_ctr = 0
start = time.perf_counter()
ciphertext_ctr = b''  # Garantir que a variável está definida

for _ in range(NUM_LOOPS):
    # Cria o objeto de cifra AES no modo CTR
    cipher = AES.new(key, AES.MODE_CTR)
    # Cria o texto cifrado
    ciphertext_ctr = cipher.encrypt(plaintext)
end = time.perf_counter()
media_ctr += end - start
# Exibe os resultados do modo CTR
results("CTR", ciphertext_ctr, media_ctr/NUM_LOOPS)


