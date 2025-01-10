import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from cryptography.fernet import Fernet
import hashlib

def send_large_number(sock, number):
    """发送一个大整数通过套接字。
    
    Args:
        sock (socket.socket): 套接字对象。
        number (int): 要发送的大整数。
    """
    number_data = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')
    chunk_size = 1024

    for index in range(0, len(number_data), chunk_size):
        chunk = number_data[index:index+chunk_size]
        sock.send(len(chunk).to_bytes(4, byteorder='big'))
        sock.send(chunk)

def receive_large_number(sock):
    """通过套接字接收一个大整数。
    
    Args:
        sock (socket.socket): 套接字对象。
        
    Returns:
        int: 接收的大整数。
    """
    number_data = b''
    while True:
        try:
            chunk_length_bytes = sock.recv(4)
            chunk_length = int.from_bytes(chunk_length_bytes, byteorder='big')
            if chunk_length == 0:
                break
            elif chunk_length < 1024:
                chunk_data = sock.recv(chunk_length)
                number_data += chunk_data
                break
            chunk_data = sock.recv(chunk_length)
            number_data += chunk_data
        except socket.timeout:
            print("接收超时")
            break
        except socket.error as e:
            print(f"接收错误: {e}")
            break

    return int.from_bytes(number_data, byteorder='big')

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def Enc(data, key):
    """
    使用AES加密数据
    :param data: 要加密的字符串或字节串
    :param key: 加密密钥（16、24或32字节）
    :return: 加密后的数据（base64编码）
    """
    # 初始化AES加密器
    cipher = AES.new(key, AES.MODE_CBC)
    
    # 对数据进行填充
    if isinstance(data, str):
        padded_data = pad(data.encode(), AES.block_size)
    else:
        padded_data = pad(data, AES.block_size)
    
    # 加密数据
    ct_bytes = cipher.encrypt(padded_data)
    
    # 将初始化向量和加密后的数据拼接，并转换为base64格式
    ct = base64.b64encode(cipher.iv + ct_bytes)
    
    return ct

def Dec(encrypted_data, key):
    """
    使用AES解密数据
    :param encrypted_data: 要解密的base64编码的数据
    :param key: 解密密钥（16、24或32字节）
    :return: 解密后的字符串或字节串
    """
    # 从base64格式转换回字节串
    ct_bytes = base64.b64decode(encrypted_data)
    
    # 提取初始化向量
    iv = ct_bytes[:AES.block_size]
    
    # 初始化AES解密器
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # 解密数据
    pt = unpad(cipher.decrypt(ct_bytes[AES.block_size:]), AES.block_size)
    
    # 如果原始数据是字符串，则解码为字符串；否则返回字节串
    if isinstance(encrypted_data, str):
        return pt.decode()
    else:
        return pt


# 生成一个固定的密钥，用于加密和解密RA
fixed_key = b'LJ3uAHMe9M_I3j6qMcKcOIGrEJ1sEOOegtjsi8SIn7o='
fernet = Fernet(fixed_key)

def commit(m, RA):
    # 使用哈希函数生成承诺c
    c = hashlib.sha256(str(m).encode() + RA).hexdigest()
    # 使用固定密钥加密RA
    d = fernet.encrypt(RA)
    return c, d

def open(m, c, d):
    # 使用固定密钥解密d，得到RA
    RA = fernet.decrypt(d)
    # 使用哈希函数验证承诺c
    c_prime = hashlib.sha256(str(m).encode() + RA).hexdigest()
    if c_prime == c:
        return RA
    return None

if __name__ == "__main__":
    # AES密钥，长度必须是16、24或32字节
    key = get_random_bytes(16)  # 生成一个16字节的随机密钥

    # 要加密的数据
    data = '1234'

    # 加密数据
    encrypted_data = Enc(data, key)
    print(f'Encrypted data: {encrypted_data}')

    # 解密数据
    decrypted_data = Dec(encrypted_data, key)
    print(f'Decrypted data: {decrypted_data.decode()}')