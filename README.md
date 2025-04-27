# 域名扫描器使用说明（DNS/HTTP版本）

## 简介

这是一个用Python编写的域名扫描器，使用DNS查询和HTTP请求方法检查域名可用性，不依赖WHOIS服务。支持扫描`.im`、`.pw`、`.gs`和`.com`这四个后缀的域名，并可以按照纯字母、纯数字或字母数字组合的方式生成和扫描域名。

## 为什么使用DNS/HTTP版本？

与基于WHOIS的域名检查相比，DNS/HTTP版本具有以下优势：
- **更高的可靠性**：不依赖WHOIS服务器，避免超时和连接问题
- **更快的检查速度**：DNS查询通常比WHOIS查询更快
- **没有查询限制**：WHOIS服务器通常会限制查询频率，而DNS查询基本没有限制
- **更简单的实现**：不需要处理不同TLD的WHOIS响应格式差异

## 功能特点

- 支持多种域名生成模式：纯字母、纯数字、字母数字混合
- 支持指定域名长度范围
- 支持多个顶级域名(TLD)扫描
- 并发查询提高效率
- 查询速率限制，避免被服务商封禁
- 支持检查点保存，可以从中断的地方继续扫描
- 结果分类保存，便于查看和分析

## 安装依赖

在使用域名扫描器前，需要安装以下依赖库：

```bash
sudo apt update && sudo apt install python3
```
```bash
sudo apt install python3-pip
```
```bash
pip3 install tqdm requests
```

## 文件结构

- `domain_generator.py`: 域名生成器模块
- `domain_checker_dns.py`: DNS/HTTP域名可用性检查模块
- `domain_scanner_dns.py`: 主程序，集成域名生成和检查功能
- `test_scanner_dns.py`: 测试脚本

## 使用方法

### 1. 生成域名列表

如果您只想生成域名列表而不检查可用性，可以使用与原版相同的`generate_lists.py`脚本（需要单独下载）。

### 2. 扫描未注册域名

要扫描未注册的域名，使用`domain_scanner_dns.py`脚本：

```bash
python3 domain_scanner_dns.py --mode letters --min-length 2 --max-length 2 --tlds .im .pw --limit 100 --workers 3
```

参数说明：
- `--mode`: 域名生成模式，可选值为`letters`(纯字母)、`digits`(纯数字)、`alphanumeric`(字母数字混合)
- `--min-length`: 域名最小长度(不包括TLD)
- `--max-length`: 域名最大长度(不包括TLD)
- `--tlds`: 要扫描的顶级域名列表
- `--limit`: 限制每个TLD生成的域名数量
- `--workers`: 并发工作线程数
- `--delay-min`: 查询延迟最小值(秒)
- `--delay-max`: 查询延迟最大值(秒)
- `--timeout`: DNS/HTTP查询超时时间(秒)
- `--retries`: 查询失败时的重试次数
- `--checkpoint-size`: 每次检查点的域名数量
- `--results-dir`: 结果保存目录，默认为`results_dns`（会自动创建）

### 3. 测试域名扫描器

要测试域名扫描器的功能是否正常，可以运行测试脚本：

```bash
python3 test_scanner_dns.py
```

## 示例

### 扫描2个字符的纯字母.im域名

```bash
python3 domain_scanner_dns.py --mode letters --min-length 2 --max-length 2 --tlds .im --workers 3
```

### 扫描3个字符的纯数字.com域名

```bash
python3 domain_scanner_dns.py --mode digits --min-length 3 --max-length 3 --tlds .com --workers 3
```

### 扫描2-3个字符的字母数字混合.pw和.gs域名

```bash
python3 domain_scanner_dns.py --mode alphanumeric --min-length 2 --max-length 3 --tlds .pw .gs --workers 3 --delay-min 1.5 --delay-max 3.0
```

## 注意事项

1. 扫描大量域名可能需要较长时间，建议先使用小范围测试
2. DNS/HTTP检查方法可能会有一定的误判率，但总体上比WHOIS方法更可靠
3. 所有输出目录会自动创建，无需手动创建文件夹
4. 默认情况下，结果保存在`results_dns`目录下


## 性能优化

- 增加`--workers`参数可以提高并发查询数量，但不要设置太高以避免网络拥塞
- 增加`--delay-min`和`--delay-max`参数可以降低被DNS服务器限制的风险
- 使用`--timeout`参数控制单个查询的最长等待时间
- 使用`--retries`参数设置查询失败时的重试次数
