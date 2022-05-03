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
    # server = remote(HOST,PORT)
    # server.send(iv)
    # server.send(ciphertext)
    # response = server. recv(1024)
    # print(response)
    # server.close()

    # server = remote(HOST,PORT)
    # server.send(iv)
    #
    # edt = bytearray(ciphertext)
    # edt[-1] = 0
    #
    # server.send(edt)
    # response = server. recv(1024)
    # print(response)
    # server.close()

    # ---------------------------------------------
    print(len(ciphertext) // AES.block_size)
    N = len(ciphertext) // AES.block_size
    p_prime_tot = bytearray(range(AES.block_size))
    p_tot = bytearray(range(AES.block_size))
    for i in range(1, N):  # because it starts with 1 and it ends with N
        initial_part = ciphertext[: (N - i - 1) * AES.block_size]
        block_to_modify = bytearray(
            ciphertext[(N - i - 1) * AES.block_size : (N - i) * AES.block_size]
        )
        last_block = ciphertext[(N - i) * AES.block_size :]
        for byte_index in reversed(range(0, AES.block_size)):
            print(block_to_modify)
            c = block_to_modify[byte_index]

            for c_prime in range(256):
                block_to_modify[byte_index] = c_prime
                to_send = initial_part + block_to_modify + last_block

                server = remote(HOST, PORT)
                server.send(iv)
                server.send(to_send)
                response = server.recv(1024)
                # print(response)
                server.close()

                if response == b"OK":
                    # print("c_prime=" + str(c_prime))
                    p_prime = c_prime ^ (AES.block_size - byte_index)
                    p_prime_tot[byte_index] = p_prime
                    p = p_prime ^ c
                    p_tot[byte_index] = p
                    # print("p_prime=" + str(p_prime))
                    print("p=" + str(p))

                    for z in reversed(range(byte_index, AES.block_size)):
                        block_to_modify[z] = p_prime_tot[z] ^ (
                            AES.block_size - byte_index + 1
                        )
                    break

    # ---------------------------------------------

    # cipher = AES.new(key, AES.MODE_CBC, iv)

    # data = b"flag{super_secret_try_brute!}"
    # padded = pad(data, AES.block_size)
    # print(len(padded))

    # ciphert = cipher.encrypt(padded)

    # print("Ciphertext: " + base64.b64encode(ciphert).decode())
    # print(ciphert)
