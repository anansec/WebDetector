# WebDetector - Web站点存活探测工具

WebDetector是一个高性能的Web站点存活探测工具，用于快速扫描和验证大量Web服务的可用性。它采用异步IO架构实现高效探测，并支持多维度检测技术。

## 🔍 核心功能

- **多协议探测**：支持HTTP/HTTPS协议检测
- **智能存活判定**：
  - DNS解析状态检测
  - ICMP响应检测（跨平台支持）
  - HTTP状态码分析（200-399视为存活）
- **静态资源过滤**：自动过滤`.js`、`.css`等静态资源
- **可视化报告**：生成JSON/CSV/HTML格式报告
- **网站截图**：对存活站点自动截图保存
- **重定向跟踪**：完整记录重定向链条

## 📦 安装依赖

```bash
pip install aiohttp beautifulsoup4 selenium tqdm
```

**截图功能额外要求**：

- Chrome浏览器
- 对应版本的[ChromeDriver](https://sites.google.com/chromium.org/driver/)

## 🚀 使用示例

### 基本用法

```
# 扫描单个站点
python web_detector.py -u http://example.com

# 批量扫描URL列表
python web_detector.py -i urls.txt -o scan_results
```

### 高级选项

```
# 启用截图和随机延迟
python web_detector.py -i targets.txt -s -d

# 使用代理和自定义请求头
python web_detector.py -u http://example.com -p http://proxy:8080 --header "Authorization: Bearer token"

# 生成所有格式报告
python web_detector.py -i urls.txt --report-format all
```

## ⚙️ 命令行参数

| 参数                | 说明                        | 默认值    |
| ------------------- | --------------------------- | --------- |
| `-i/--input`        | 包含URL列表的输入文件       | 无        |
| `-u/--url`          | 单个目标URL                 | 无        |
| `-o/--output`       | 结果输出目录                | `results` |
| `-t/--threads`      | 并发线程数                  | `50`      |
| `-T/--timeout`      | 请求超时时间(秒)            | `10`      |
| `-r/--retries`      | 失败重试次数                | `2`       |
| `-s/--screenshot`   | 启用网站截图功能            | 禁用      |
| `-d/--random-delay` | 启用随机延迟                | 禁用      |
| `-p/--proxy`        | 代理服务器地址              | 无        |
| `--no-redirect`     | 禁用重定向跟踪              | 启用      |
| `--header`          | 自定义请求头                | 无        |
| `--report-format`   | 报告格式(json/csv/html/all) | `json`    |

## 📊 输出报告

### 控制台输出

```
+============================================================+
| URL                        | 状态码 | 标题       | 服务器      | 状态 | DNS解析 | ICMP响应 |
+------------------------------------------------------------+
| http://example.com         |  200  | Example... | nginx     | 存活 | 成功   | 响应     |
| http://test.com/login      |  403  | Login...   | Apache    | 疑似 | 成功   | 响应     |
+============================================================+
```

### 文件输出

- `report_<域名>_<时间戳>.json`：完整探测结果(JSON)
- `report_<域名>_<时间戳>.csv`：结构化数据(CSV)
- `report_<域名>_<时间戳>.html`：可视化报告(HTML)
- `alive_urls.txt`：存活站点列表
- `suspicious_urls.txt`：可疑站点列表
- `dead_urls.txt`：无效站点列表
- `screenshots/`：网站截图目录

## 🧩 技术架构

```
graph TD
    A[输入] --> B[URL规范化]
    B --> C[异步探测]
    C --> D[DNS解析检测]
    C --> E[ICMP响应检测]
    C --> F[HTTP请求分析]
    F --> G[静态资源过滤]
    F --> H[重定向跟踪]
    G --> I[结果分类]
    H --> I
    I --> J[报告生成]
    J --> K[JSON/CSV/HTML]
    I --> L[网站截图]
```

## ⚠️ 注意事项

1. 截图功能需要安装Chrome浏览器和对应版本的ChromeDriver
2. 大规模扫描时建议启用随机延迟(`-d`参数)避免触发防护机制
3. ICMP检测在Linux/macOS需要root权限

## 📜 许可证

本项目采用MIT许可证。详细信息请查看LICENSE文件。
