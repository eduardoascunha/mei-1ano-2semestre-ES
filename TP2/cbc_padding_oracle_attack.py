import base64
from cbc_padding_oracle import decryption_oracle, encryption_oracle

def padding_oracle_attack(ciphertext, iv):
    block_size = 16  # Tamanho do bloco para AES (128 bits)
    
    # Dividir o ciphertext em blocos, incluindo o IV
    cipher_blocks = [iv] + [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_plaintext = b''  # Resultado final da decifragem

    # Iterar por cada bloco de cifra (exceto o IV)
    for block_index in range(1, len(cipher_blocks)):
        intermediate_values = bytearray(block_size)  # Valores intermédios para decifrar o bloco
        decrypted_block = bytearray(block_size)  # Bloco de plaintext recuperado

        # Percorrer cada byte do bloco (da direita para a esquerda)
        for byte_pos in range(block_size - 1, -1, -1):
            expected_padding = block_size - byte_pos  # Valor esperado de padding PKCS7
            modified_prev_block = bytearray(cipher_blocks[block_index - 1])  # Clonar bloco anterior

            # Ajustar os bytes já descobertos para corresponder ao padding esperado
            for i in range(byte_pos + 1, block_size):
                modified_prev_block[i] = intermediate_values[i] ^ expected_padding
            
            # Tentar todas as possibilidades de 0x00 a 0xFF
            valid_padding_found = False
            for guess in range(256):
                modified_prev_block[byte_pos] = guess
                
                # Verificar se o padding é válido
                if decryption_oracle(cipher_blocks[block_index], bytes(modified_prev_block)):
                    print(f"[*] Padding válido encontrado: guess={guess} para byte {byte_pos} no bloco {block_index}")

                    # Calcular valores intermédios e o byte decifrado
                    intermediate_values[byte_pos] = guess ^ expected_padding
                    decrypted_block[byte_pos] = intermediate_values[byte_pos] ^ cipher_blocks[block_index - 1][byte_pos]
                    
                    # Confirmar se o padding é realmente válido (evitar falsos positivos)
                    if byte_pos > 0:
                        modified_test_block = bytearray(modified_prev_block)
                        modified_test_block[byte_pos - 1] ^= 1  # Alterar um byte anterior

                        if not decryption_oracle(cipher_blocks[block_index], bytes(modified_test_block)):
                            print("Falso positivo!")
                            continue  # Falso positivo, continuar a tentar
                    
                    valid_padding_found = True
                    break  # Sair do loop quando um padding válido for encontrado
            
            if not valid_padding_found:
                print(f"Falha ao encontrar padding válido para byte {byte_pos} no bloco {block_index}")
                return None  # Ataque falhou

        decrypted_plaintext += decrypted_block

    # Remover o padding PKCS#7
    padding_length = decrypted_plaintext[-1]
    if 1 <= padding_length <= block_size and all(decrypted_plaintext[-i] == padding_length for i in range(1, padding_length + 1)):
        ret = decrypted_plaintext[:-padding_length]

    return ret

def main():
    """
    Função principal para executar o ataque de oracle de padding.
    """
    ciphertext, iv = encryption_oracle()  # Obter texto cifrado e IV
    print("Texto cifrado original:", ciphertext.hex())
    
    decrypted = padding_oracle_attack(ciphertext, iv)  # Executar o ataque
    if decrypted:
        print("Texto decifrado pelo ataque (hex):", decrypted.hex())
        
        try:
            decrypted_str = decrypted.decode('utf-8')  # Tentar converter para string legível
            print("Texto decifrado pelo ataque:", decrypted_str)
            
            # Verificar se corresponde a um dos textos originais em base64
            original_strings = [
                "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
            ]
            
            for base64_str in original_strings:
                original_text = base64.b64decode(base64_str).decode('utf-8')
                if decrypted_str == original_text:
                    print("\nSUCESSO!)")
                    print("string:", base64_str)
                    print("Texto original:", original_text)
                    break
        except Exception as e:
            print("Erro:", str(e))
    else:
        print("Ataque falhou.")

if __name__ == "__main__":
    main()
