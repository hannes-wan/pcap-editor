# PCAP-EDITOR

```

██████╗  ██████╗ █████╗ ██████╗     ███████╗██████╗ ██╗██████╗ ██████╗ ███████╗██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     ███████║██████╔╝    █████╗  ██║  ██║██║██║  ██║██║  ██║█████╗  ██████╔╝
██╔═══╝ ██║     ██╔══██║██╔═══╝     ██╔══╝  ██║  ██║██║██║  ██║██║  ██║██╔══╝  ██╔══██╗
██║     ╚██████╗██║  ██║██║         ███████╗██████╔╝██║██████╔╝██████╔╝███████╗██║  ██║
╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═════╝ ╚═╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

```

> 多功能网络数据包处理工具集

## 功能特性

PCAP-EDITOR 提供以下强大的 PCAP 文件处理功能：

- ⏱️ **时间轴压缩**：加速网络流量时间线
- ⏳ **时间轴拉伸**：延长网络流量时间线
- 🧪 **数据包稀释**：减少数据包数量，保持时间分布
- 📦 **数据包增强**：复制数据包以增加流量密度
- 🔍 **乱序检测**：识别时间戳乱序的数据包
- 🔄 **文件比较**：对比两个 PCAP 文件的内容差异（支持时间戳忽略）

## 安装指南

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/hannes-wan/pcap-editor.git
cd pcap-editor

# 构建项目
cargo build --release

# 安装到系统路径
cargo install --path .
```

### 二进制发布版

从 [Release 页面](https://github.com/hannes-wan/pcap-editor/releases) 下载预编译二进制文件。

## 使用说明

### 基本命令结构

```bash
pcap-editor [OPTIONS] <COMMAND>
```

### 全局选项

| 选项                      | 描述                                           | 默认值 |
| ------------------------- | ---------------------------------------------- | ------ |
| `-l, --log-level <LEVEL>` | 设置日志级别 (trace/debug/info/warn/error/off) | info   |

### 功能命令

#### 1. 时间轴压缩

```bash
pcap-editor time-compress \
    -i input.pcap \
    -o compressed.pcap \
    -f 2.0
```

#### 2. 时间轴拉伸

```bash
pcap-editor time-stretch \
    -i input.pcap \
    -o stretched.pcap \
    -f 0.5
```

#### 3. 数据包稀释

```bash
pcap-editor dilute \
    -i input.pcap \
    -o diluted.pcap \
    -f 3
```

#### 4. 数据包增强

```bash
pcap-editor augment \
    -i input.pcap \
    -o augmented.pcap \
    -f 5
```

#### 5. 乱序检测

```bash
pcap-editor disorder-detect \
    -i input.pcap
```

#### 6. 文件比较

```bash
# 包含时间戳比较
pcap-editor compare \
    -r base.pcap \
    -c modified.pcap

# 忽略时间戳比较
pcap-editor compare \
    -r base.pcap \
    -c modified.pcap \
    --ignore-timestamp
```

## 输出示例

### 文件比较结果

```
PCAP内容比较结果:
- 比较模式: 忽略时间戳
- 基准文件包数: 1000
- 对比文件包数: 980
- 丢失包数: 20
- 多余包数: 0

丢失包详情 (存在于基准文件但不在对比文件中):
  [基准包 42] 长度: 128 字节, 哈希: 3a7d8f1e2b5c9d0a
  [基准包 87] 长度: 256 字节, 哈希: 5f3a8b1e2c9d7f0a

⚠️ 发现内容差异
```

## 贡献指南

欢迎通过 Issues 和 Pull Requests 参与贡献：

1. 提交功能请求或错误报告
2. Fork 仓库并创建特性分支
3. 提交代码变更并确保通过测试
4. 创建 Pull Request 并描述变更内容

## 许可证

本项目采用 [MIT 许可证](LICENSE)。
