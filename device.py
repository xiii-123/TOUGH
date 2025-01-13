import socket
from DiffieHellman import DiffieHellman
from SAS import SASParty
from utils import send_large_number, receive_large_number, Enc, Dec, encrypt_data, bytes_to_public_key
import subprocess
import socket

ports = [12345, 12346]
for i in range(len(ports)):
    # 初始化socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', ports[i]))

    # # Diffie-Hellman 密钥交换
    # client_diffie_hellman = DiffieHellman()

    # # 发送客户端公钥
    # client_public_key = client_diffie_hellman.publicKey
    # send_large_number(client_socket, client_public_key)

    # # 接收服务器公钥
    # server_public_key = receive_large_number(client_socket)
    # client_diffie_hellman.genKey(server_public_key)

    # # 现在我们有了共享密钥
    # shared_secret = client_diffie_hellman.key
    # shared_secret = shared_secret[:32]
    # print(f"Shared secret generated: {shared_secret.hex()}")

    # 初始化 SAS-MA
    sas_party = SASParty()

    password = "123456"

    # 接收公钥
    pubKey_bytes = client_socket.recv(1024)
    print(f"Received public key: {pubKey_bytes.hex()[:32]}")
    pubKey = bytes_to_public_key(pubKey_bytes)

    # 接受承诺
    commitment = client_socket.recv(1024).decode()
    print(f"Received commitment: {commitment}")

    # 发送R_B
    R_B = sas_party.get_random_value()
    client_socket.send(R_B)
    print(f"Sent R_B: {R_B.hex()}")

    # 接受解承诺
    decommitment = client_socket.recv(1024)
    print(f"Received decommitment: {decommitment[:32].hex()}")

    # 计算R_A
    R_A = sas_party.open(pubKey_bytes, commitment, decommitment)
    print(f"R_A: {R_A.hex()}")

    # 计算SAS
    client_sas = sas_party.compute_sas(R_A)
    # 假设SAS也是一个整数，将其转换为字节串
    print(f"Please verify the SAS string with party{i+1}: {client_sas}")

    user_input = input("yes or no: ")

    if user_input == "no":
        print("SAS validation failed!")
        os._exit(1)
    print("SAS validation succeeded!")

    ciphertext = encrypt_data(pubKey, password)
    client_socket.send(ciphertext)
    print(f"Sent ciphertext: {ciphertext.hex()[:32]}")

    # 关闭连接
    client_socket.close()
    print("==============================")