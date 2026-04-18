# 时序图: Crypto Plus 整个工程

以下时序图展示了整个工程的主要模块和功能调用流程。

```plantuml
@startuml
actor User
participant "CryptoPlus Library" as Library
participant "CryptoPlus Asymmetric" as Asymmetric
participant "CryptoPlus Compatible" as Compatible
participant "CryptoPlus Key Management" as KeyManagement
participant "CryptoPlus Encryption" as Encryption
participant "CryptoPlus Signature" as Signature

User -> Library: 初始化库
Library -> Asymmetric: 调用非对称加密功能
Library -> Compatible: 调用兼容性功能
Library -> KeyManagement: 管理密钥
Library -> Encryption: 加密数据
Library -> Signature: 签名数据

User -> Asymmetric: 使用非对称加密
Asymmetric -> KeyManagement: 获取密钥
Asymmetric -> Encryption: 加密数据
Asymmetric -> Signature: 验证签名

User -> Compatible: 使用兼容性功能
Compatible -> Library: 替换目标函数
Compatible -> Library: 忽略警告

User -> KeyManagement: 管理密钥
KeyManagement -> Library: 导入/导出密钥

User -> Encryption: 加密数据
Encryption -> KeyManagement: 获取密钥
Encryption -> Library: 加密数据

User -> Signature: 签名数据
Signature -> KeyManagement: 获取密钥
Signature -> Library: 签名数据
@enduml