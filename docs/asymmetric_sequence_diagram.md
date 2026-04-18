# 时序图: Crypto Plus Asymmetric 模块

以下时序图展示了 `CryptoPlus` 类的主要方法调用流程。

```plantuml
@startuml
actor User
participant "CryptoPlus" as CryptoPlus
participant "KeyPair" as KeyPair
participant "CertificateBuilder" as CertificateBuilder

User -> CryptoPlus: 初始化 (key)
CryptoPlus -> KeyPair: 构造 KeyPair
CryptoPlus -> CryptoPlus: 构造 keypair

User -> CryptoPlus: 加密 (encrypt)
CryptoPlus -> CryptoPlus: 使用 public_key 加密

User -> CryptoPlus: 解密 (decrypt)
CryptoPlus -> CryptoPlus: 使用 private_key 解密

User -> CryptoPlus: 签名 (sign)
CryptoPlus -> CryptoPlus: 使用 private_key 生成签名

User -> CryptoPlus: 验证签名 (verify)
CryptoPlus -> CryptoPlus: 使用 public_key 验证签名

User -> CryptoPlus: 导出证书 (dump_cert)
CryptoPlus -> CertificateBuilder: 构造证书
CryptoPlus -> User: 返回证书
@enduml