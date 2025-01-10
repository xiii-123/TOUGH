import os
import hashlib
from utils import commit, open


class SASParty:
    def __init__(self, k=128, sas_length=6):
        self.k = k  # 随机数长度
        self.random_value = os.urandom(k // 8)  # 每个角色生成自己的随机数
        self.sas_length = sas_length  # SAS 长度
        self.commitment = None
        self.decommitment = None

    def commit(self, message):
        """
        生成承诺值 (commitment, decommitment)
        """
        return commit(message, self.random_value)

    def open(self, message, commitement, decommitment):
        """
        验证对方的承诺
        """
        return open(message, commitement, decommitment)

    def compute_sas(self, other_random_value):
        """
        使用对方的随机数计算 SAS
        """
        sas_raw = bytes(a ^ b for a, b in zip(self.random_value, other_random_value))
        # 生成短认证字符串
        return hashlib.sha256(sas_raw).hexdigest()[:self.sas_length]

    def get_random_value(self):
        """
        获取本地的随机值，用于发送给对方
        """
        return self.random_value


def sas_protocol_simulation():
    # 初始化 Alice 和 Bob
    alice = SASParty()
    bob = SASParty()

    # Alice 创建承诺并发送 (m, c) 给 Bob
    message = "Hello, Bob!"
    alice_commitment,alice_decommitment = alice.commit(message)
    print(f"alice commitment: {alice_commitment}")

    print(f"alice sends message: {message} and commitment to bob")

    # Bob 接收消息和承诺，生成自己的随机值并发送给 Alice
    bob_random_value = bob.get_random_value()
    print(f"bob sends random value to alice: {bob_random_value.hex()}")

    # Alice 接收 Bob 的随机值，发送 decommitment 给 Bob
    print(f"alice sends decommitment to bob: {alice_decommitment.hex()}")

    # Bob 验证 Alice 的承诺
    R_A = bob.open(message, alice_commitment, alice_decommitment)

    if not R_A:
        print("Commitment verification failed. The communication may have been tampered!")
        return

    print(f"bob successfully verified the commitment from alice")

    # 双方计算 SAS
    sas_alice = alice.compute_sas(bob.get_random_value())
    sas_bob = bob.compute_sas(R_A)

    print(f"Alice computed SAS: {sas_alice}")
    print(f"Bob computed SAS: {sas_bob}")

    # 验证 SAS 是否一致
    if sas_alice == sas_bob:
        print("SAS validation succeeded! The message is authentic and shared key matches.")
        print(f"Final SAS: {sas_alice}")
    else:
        print("SAS validation failed! Communication may have been tampered.")


if __name__ == "__main__":
    # 运行 SAS 协议模拟
    sas_protocol_simulation()
