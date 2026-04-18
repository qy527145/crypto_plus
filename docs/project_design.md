# 项目设计: Crypto Plus

## 项目简介
Crypto Plus 是一个加密相关的 Python 库，提供了多种加密、签名和密钥管理功能。项目包含核心代码模块、测试文件以及开发文档。

---

## 项目结构

### 代码模块 (`src/crypto_plus`)
- **`__init__.py`**: 初始化模块。
- **`asymmetric.py`**: 实现非对称加密相关功能。
- **`base.py`**: 提供基础功能。
- **`compatible.py`**: 处理兼容性问题。
- **`encrypt.py`**: 实现加密功能。
- **`key.py`**: 管理密钥。
- **`sign.py`**: 实现签名功能。

### 测试模块 (`tests`)
- **`tests/asymmetric`**: 测试非对称加密功能。
  - `test_dump.py`: 测试数据导出功能。
  - `test_encrypt.py`: 测试加密功能。
  - `test_sign.py`: 测试签名功能。
- **`tests/crypto_plus`**: 包含示例测试文件。

### 文档 (`docs`)
- **`index.md`**: 项目主页，包含 MkDocs 命令和项目布局说明。
- **`development.md`**: 开发手册，详细描述了环境初始化、测试、构建和发布流程。

---

## 开发流程

### 环境初始化
1. 安装 Poetry:
   ```bash
   pip install poetry
   ```
2. 克隆仓库:
   ```shell script
   git clone https://github.com/qy527145/crypto_plus.git
   ```
3. 安装依赖:
   ```shell script
   poetry install -v
   pre-commit install
   ```

### 测试
- 运行代码规范化检查:
  ```shell script
  pre-commit run -a
  ```
- 使用 Tox 进行多版本测试:
  ```shell script
  tox
  ```

### 构建与发布
- 构建包:
  ```shell script
  poetry build
  ```
- 发布到 PyPI:
  ```shell script
  poetry publish
  ```

---

## 项目设计图

```plantuml
@startuml
package "Crypto Plus 项目" {
    package "代码模块" {
        class asymmetric.py
        class base.py
        class compatible.py
        class encrypt.py
        class key.py
        class sign.py
    }
    package "测试模块" {
        class tests/asymmetric
        class tests/crypto_plus
    }
    package "文档" {
        class index.md
        class development.md
    }
}
@enduml