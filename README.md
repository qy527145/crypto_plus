# [Crypto Plus](https://github.com/qy527145/crypto_plus)

## 1. 概览

一个易用的加解密、签名、证书工具，支持多种加密算法（如 RSA、DSA、ECDSA），并提供便捷的文件导入导出功能。
目前已发布到 [PyPI](https://pypi.org/project/crypto_plus)。

### 项目特点
- 支持多种加密算法：RSA、DSA、ECDSA。
- 提供加解密、签名验签功能。
- 支持自签名证书的生成与导出。
- 易于集成，支持文件导入导出。

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
assert rsa.decrypt(ciphertext) == plaintext

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

阅读 [开发手册](./docs/development.md)。

### 贡献指南

欢迎贡献代码！请参考以下步骤：
1. Fork 本仓库。
2. 创建一个新的分支：`git checkout -b feature-branch`。
3. 提交您的更改：`git commit -m 'Add some feature'`。
4. 推送到分支：`git push origin feature-branch`。
5. 创建一个 Pull Request。

我们期待您的贡献！
