import hashlib
import random
from typing import List
class SchnorrSignature:
    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s
def generate_key_pair():
    p = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    q = (p - 1) // 2  # q是一个大素数
    g = 2

    x = random.randint(1, q)  # 生成私钥x，随机选取一个整数
    y = pow(g, x, p)  # 生成公钥y
    

    return x, y
   
    
def sign_message(message: str, x: int) -> SchnorrSignature:
    p = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    q = (p - 1) // 2
    g = 2

    k = random.randint(1, q)  # 随机选择一个整数k

    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)  # 计算消息的哈希值
    r = pow(g, k, p)  # 计算r = g^k mod p

    e = h + r  # 计算挑战值e = H(m) + r
    s = (k - x * e) % q  # 计算签名值s = (k - x * e) mod q

    signature = SchnorrSignature(r, s)
    return signature


def verify_signature(message: str, y: int, signature: SchnorrSignature) -> bool:
    p = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    g = 2

    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)  # 计算消息的哈希值
    e = h + signature.r  # 计算挑战值e = H(m) + r

    u1 = (signature.s * pow(g, e, p)) % p
    u2 = (signature.r * pow(y, e, p)) % p

    v = (pow(g, u1, p) * pow(y, u2, p)) % p  # 计算v = g^u1 * y^u2 mod p

    return v == signature.r


def batch_verify_signatures(messages: List[str], public_keys: List[int], signatures: List[SchnorrSignature]) -> bool:
    if len(messages) != len(public_keys) or len(messages) != len(signatures):
        return False

    aggregated_signature = SchnorrSignature(0, 0)

    for i in range(len(messages)):
        message = messages[i]
        public_key = public_keys[i]
        signature = signatures[i]

        aggregated_signature.r += signature.r
        aggregated_signature.s += signature.s

    return verify_signature('Aggregated Message', aggregated_signature.r, aggregated_signature)


# 示例用法
# 生成3个密钥对，利用已写函数生成三个消息的公钥和私钥
key_pairs = [generate_key_pair() for _ in range(3)]
messages = ['message 1', 'message 2', 'message 3']

# 批量签名
signatures = [sign_message(message, key_pair[0]) for message, key_pair in zip(messages, key_pairs)]


# 提取公钥
public_keys = [key_pair[1] for key_pair in key_pairs]

# 使用批量验证签名
valid = batch_verify_signatures(messages, public_keys, signatures)

print("Valid signature:", valid)
