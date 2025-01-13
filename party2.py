import socket
from DiffieHellman import DiffieHellman
from SAS import SASParty
from utils import send_large_number, receive_large_number, Enc, Dec, generate_keys, decrypt_data, public_key_to_bytes
import subprocess
import os

# 初始化socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('127.0.0.1', 12345))
serversocket.listen(5)
print("Server is listening for incoming connections...")

# 接受客户端连接
clientsocket, address = serversocket.accept()
print(f"Connection from {address} has been established.")

# # Diffie-Hellman 密钥交换
# server_diffie_hellman = DiffieHellman()

# # 接收客户端公钥
# client_public_key = receive_large_number(clientsocket)

# # 发送服务器公钥
# server_public_key = server_diffie_hellman.publicKey
# send_large_number(clientsocket, server_public_key)

# # 生成共享密钥
# server_diffie_hellman.genKey(client_public_key)
# shared_secret = server_diffie_hellman.key
# shared_secret = shared_secret[:32]
# print(f"Shared secret generated: {shared_secret.hex()}")

# 初始化 SAS-MA
sas_party = SASParty()
print("Server SAS-MA party initialized.")

# 初始化公私钥
secKey, pubKey = generate_keys()

# 发送公钥
pubKey_byte = public_key_to_bytes(pubKey)
clientsocket.send(pubKey_byte)
print(f"Sending public key: {pubKey_byte.hex()[:32]}")

# 生成并发送承诺
commitment, decommitment = sas_party.commit(pubKey_byte)
clientsocket.send(commitment.encode())
print(f"Sending commitment: {commitment}")

# 接收R_B
R_B = clientsocket.recv(256)
# commitment = Dec(commitment_bytes, shared_secret).decode()
print(f"Received R_B: {R_B.hex()}")


# 发送解承诺
clientsocket.send(decommitment)
print(f"Sending decommitment: {decommitment[:32].hex()}")

# 计算SAS
server_sas = sas_party.compute_sas(R_B)
print(f"Please verify the SAS string of party1: {server_sas}")

# 接受ciphertext
ciphertext = clientsocket.recv(1024)
password = decrypt_data(secKey, ciphertext)
print(f"Received password: {password}")

# 关闭连接
clientsocket.close()
serversocket.close()

# 可执行文件的路径
executable_path1 = f'CRISP/CHIP/gen_pwd_file'
executable_path2 = f'CRISP/CHIP/key_exchange'

# 参数列表（不包括重定向符号和文件名）
arguments1 = ['MyNetwork', '\'{message}\'', 'Bob']
arguments2 = ['bob.pwd']

# 运行可执行文件并传递参数，同时重定向输出到bob.pwd
with open('bob.pwd', 'w') as output_file:
    result = subprocess.run([executable_path1] + arguments1, stdout=output_file, stderr=subprocess.PIPE, text=True)

# 输出错误信息（如果有的话）
print(result.stderr)

# 检查返回码
if result.returncode == 0:
    print("创建文件bob.pwd成功")

# 运行可执行文件
result = subprocess.Popen([executable_path2] + arguments2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# 等待进程完成并获取输出
stdout, stderr = result.communicate()

# 显示执行的输出
print("stdout:")
print(stdout)

# 显示错误信息（如果有的话）
print("stderr:")
print(stderr)

# 检查返回码
print(f"程序返回码：{result.returncode}")