# 开发手册

## 初始化环境

- 准备

```bash
pip install poetry
```

- 克隆仓库

```shell script
git clone https://github.com/qy527145/crypto_plus.git
```

- 安装依赖

```shell script
# 安装依赖
poetry install -v
# 安装git钩子
pre-commit install
```

## Delivery

### 测试

```shell script
# 规范化代码
pre-commit run -a
# 多版本测试
tox
```

### Git 标签

添加标签

```shell script
git tag -a v0.1.0
```

### Build

构件包

```shell script
poetry build
```

### 发布

发布到pypi, 可以使用 `--repository https://pypi.org/simple` 指定远程包仓库

```shell script
poetry publish
```

## 开发手册

### Pycharm Configuration

Open project use Pycharm.

#### Module can not import in src

Check menu bar, click `File` --> `Settings` --> `Project Settings` --> `Project Structure` .
Mark `src` and `tests` directory as sources.

#### Enable pytest

Click `File` --> `Settings` --> `Tools` --> `Python Integrated Tools` --> `Testing` --> `Default runner`, then select
`pytest`.

If you run test by `Unittests` before, you should delete configuration. Open `Edit Run/Debug configurations dialog` in
In the upper right corner of Pycharm window, then delete configuration.

### Others

You should confirm `src` directory in `sys.path`. You can add it by `sys.path.extend(['/tmp/demo/src'])` if it not
exist.
