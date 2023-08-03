import ecdsa
import random
import hashlib
gen = ecdsa.NIST256p.generator
order = gen.order()
#选取NIST256p椭圆曲线
# 生成私钥d_A
d_A = random.randrange(1,order-1)
# 生成公私钥对象
public_key = ecdsa.ecdsa.Public_key(gen,gen * d_A)
private_key = ecdsa.ecdsa.Private_key(public_key,d_A)
message = "message"
m = int(hashlib.sha1(message.encode("utf8")).hexdigest(),16)
# 临时密钥
k = random.randrange(1,order-1)
# 签名
signature = private_key.sign(m,k)
r = signature.r 
s = signature.s 
