import socket
from DiffieHellman import DiffieHellman
from SAS import SASParty
from utils import send_large_number, receive_large_number, Enc, Dec
import subprocess
import socket

ports = [12345, 12346]
for i in range(len(ports)):
    # 初始化socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', ports[i]))

    # Diffie-Hellman 密钥交换
    client_diffie_hellman = DiffieHellman()

    # 发送客户端公钥
    client_public_key = client_diffie_hellman.publicKey
    send_large_number(client_socket, client_public_key)

    # 接收服务器公钥
    server_public_key = receive_large_number(client_socket)
    client_diffie_hellman.genKey(server_public_key)

    # 现在我们有了共享密钥
    shared_secret = client_diffie_hellman.key
    shared_secret = shared_secret[:32]
    print(f"Shared secret generated: {shared_secret.hex()}")

    # 初始化 SAS-MA
    client_sas_party = SASParty()

    # 创建消息和承诺并发送给服务器
    message = "Pa$$Word"
    commitment,decommitment = client_sas_party.commit(message)
    client_socket.send(Enc(message, shared_secret))
    print(f"Sending message: {message}")
    # commitment将其转换为字节串
    client_socket.send(Enc(commitment, shared_secret))
    print(f"Sending commitment: {commitment}")

    # 接收服务器的随机值
    R_B = client_socket.recv(1024)
    R_B = Dec(R_B, shared_secret)
    print(f"Received R_A: {R_B.hex()}")

    # 发送解承诺给服务器
    client_socket.send(Enc(decommitment,shared_secret))
    print(f"Sending decommitment: {decommitment[:32].hex()}")

    # 计算SAS
    client_sas = client_sas_party.compute_sas(R_B)
    # 假设SAS也是一个整数，将其转换为字节串
    print(f"Computed SAS with party{i+1}: {client_sas}")

    # 关闭连接
    client_socket.close()
    print("==============================")