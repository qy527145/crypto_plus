# [Crypto Plus](https://github.com/qy527145/crypto_plus)

## 1. 概览

一个易用的加解密、签名、证书工具。
目前已发布到[pypi](https://pypi.org/project/crypto_plus)。


## 2. 使用

### 2.1 安装

```bash
pip install crypto_plus
```

### 2.2 使用

```python
from crypto_plus import CryptoPlus

# 目前支持RSA、DSA、ECDSA
rsa = CryptoPlus.generate_rsa()
# dsa = CryptoPlus.generate_dsa()
# ecdsa = CryptoPlus.generate_ecdsa()

# 加解密
plaintext = b'plaintext bytes'
ciphertext = rsa.encrypt(plaintext)
assert rsa.decrypt(ciphertext) == ciphertext

# 签名、验签
message = b'message bytes'
signature = rsa.sign(message)
rsa.verify(message, signature)

# 导出自签名证书
rsa.dump_cert(subject_name="subject", issuer_name="issuer")

# 导入导出文件
rsa.dump()
rsa_from_file = CryptoPlus.load()

```

## 3. 开发

阅读 [开发手册](./docs/development.md).
