import os

os.environ["PWNLIB_NOTERM"] = "True"
os.environ["PWNLIB_SILENT"] = "True"
from pwn import *

from myconfig import HOST, PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext
from mydata import cbc_oracle_key as key

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

if __name__ == "__main__":
    import os
os.environ["PWNLIB_NOTERM"] = "True"
os.environ["PWNLIB_SILENT"] = "True"
from pwn import *

from Crypto.Cipher import AES

if __name__ == "__main__":
    print("Starting to decrypting the plaintext...")
    N = len(ciphertext) // AES.block_size
    p_prime_tot = bytearray(range(AES.block_size))
    p_tot = []
    for i in range(1, N + 1):  # because it starts with 1 and it ends with N
        if (N - i - 1) < 0:
            initial_part = ciphertext[:0]
            block_to_modify = bytearray(iv)
        else:
            initial_part = ciphertext[: (N - i - 1) * AES.block_size]
            block_to_modify = bytearray(
                ciphertext[(N - i - 1) * AES.block_size : (N - i) * AES.block_size]
            )
        last_block = ciphertext[(N - i) * AES.block_size : (N - i + 1) * AES.block_size]
        for byte_index in reversed(range(0, AES.block_size)):
            c = block_to_modify[byte_index]

            for c_prime in range(256):
                block_to_modify[byte_index] = c_prime
                to_send = initial_part + block_to_modify + last_block

                server = remote(HOST, PORT)
                server.send(iv)
                server.send(to_send)
                response = server.recv(1024)
                server.close()

                if response == b"OK":
                    p_prime = c_prime ^ (AES.block_size - byte_index)
                    p_prime_tot[byte_index] = p_prime
                    p = p_prime ^ c
                    p_tot.insert(0, p)

                    for z in reversed(range(byte_index, AES.block_size)):
                        block_to_modify[z] = p_prime_tot[z] ^ (
                            AES.block_size - byte_index + 1
                        )
                    break
    print("...decryption ends.")
    print("Plaintext:   " + bytearray(p_tot).decode())
