import socket
from DiffieHellman import DiffieHellman
from SAS import SASParty
from utils import send_large_number, receive_large_number, Enc, Dec
import subprocess

# 初始化socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('127.0.0.1', 12346))
serversocket.listen(5)
print("Server is listening for incoming connections...")

# 接受客户端连接
clientsocket, address = serversocket.accept()
print(f"Connection from {address} has been established.")

# Diffie-Hellman 密钥交换
server_diffie_hellman = DiffieHellman()

# 接收客户端公钥
client_public_key = receive_large_number(clientsocket)

# 发送服务器公钥
server_public_key = server_diffie_hellman.publicKey
send_large_number(clientsocket, server_public_key)

# 生成共享密钥
server_diffie_hellman.genKey(client_public_key)
shared_secret = server_diffie_hellman.key
shared_secret = shared_secret[:32]
print(f"Shared secret generated: {shared_secret.hex()}")

# 初始化 SAS-MA
server_sas_party = SASParty()
print("Server SAS-MA party initialized.")

# 接收消息
message_byte = clientsocket.recv(1024)
message = Dec(message_byte, shared_secret).decode()
print(f"Received message: {message}")

# 接收承诺
commitment_bytes = clientsocket.recv(1024)
commitment = Dec(commitment_bytes, shared_secret).decode()
print(f"Received commitment: {commitment}")

# 生成随机值并发送给客户端
R_B = server_sas_party.get_random_value()
clientsocket.send(Enc(R_B, shared_secret))
print(f"Sent R_B: {R_B.hex()}")

# 接收解承诺
decommitment = clientsocket.recv(1024)
decommitment = Dec(decommitment, shared_secret)
print(f"Received decommitment: {decommitment[:32].hex()}")

# 验证解承诺
R_A = server_sas_party.open(message, commitment, decommitment)
if R_A:

    # 验证SAS
    SAS = server_sas_party.compute_sas(R_A)
    print(f"Computed SAS: {SAS}")
else:
    print("Commitment validation failed. Communication may have been tampered.")

# 关闭连接
clientsocket.close()
serversocket.close()

# 可执行文件的路径
executable_path1 = f'CRISP/CHIP/gen_pwd_file'
executable_path2 = f'CRISP/CHIP/key_exchange'

# 参数列表（不包括重定向符号和文件名）
arguments1 = ['MyNetwork', '\'{message}\'', 'Alice']
arguments2 = ['alice.pwd']

# 运行可执行文件并传递参数，同时重定向输出到alice.pwd
with open('alice.pwd', 'w') as output_file:
    result = subprocess.run([executable_path1] + arguments1, stdout=output_file, stderr=subprocess.PIPE, text=True)

# 输出错误信息（如果有的话）
print(result.stderr)

# 检查返回码
if result.returncode == 0:
    print("创建文件Alice.pwd成功！")

# 运行可执行文件并获取输出
result = subprocess.run([executable_path2] + arguments2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# 显示执行的输出
print("stdout:")
print(result.stdout)

# 显示错误信息（如果有的话）
print("stderr:")
print(result.stderr)

# 检查返回码
print(f"程序返回码：{result.returncode}")