#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import asyncio
import aiohttp
import csv
import json
import os
import random
import re
import sys
import time
import socket
import subprocess
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse, urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from typing import List, Dict

# ======================== 配置区域 ========================
DEFAULT_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
]

STATIC_EXTENSIONS = ['.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']

# ======================== 核心探测引擎 ========================
class WebDetector:
    def __init__(self, 
                 input_file: str = None,
                 single_url: str = None,
                 output_dir: str = "results", 
                 threads: int = 50, 
                 timeout: int = 10, 
                 max_retries: int = 2,
                 follow_redirects: bool = True,
                 screenshot: bool = False,
                 random_delay: bool = False,
                 proxy: str = None,
                 custom_headers: Dict = None,
                 report_format: str = "json"):
        
        self.input_file = input_file
        self.single_url = single_url
        self.output_dir = output_dir
        self.threads = threads
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.screenshot = screenshot
        self.random_delay = random_delay
        self.proxy = proxy
        self.custom_headers = custom_headers or {}
        self.report_format = report_format.lower()
        self.results = []
        self.screenshot_dir = os.path.join(output_dir, "screenshots")
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        if screenshot:
            os.makedirs(self.screenshot_dir, exist_ok=True)
    
    def run(self):
        """执行探测流程"""
        print(f"\n\033[34m[+] Web站点存活探测启动 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
        print(f"   线程数: {self.threads}, 超时: {self.timeout}秒, 重试次数: {self.max_retries}")
        print(f"   跟随重定向: {'是' if self.follow_redirects else '否'}")
        print(f"   截图功能: {'启用' if self.screenshot else '禁用'}")
        print(f"   报告格式: {self.report_format.upper()}")
        
        start_time = time.time()
        urls = self._load_urls()
        
        if not urls:
            print("\033[31m[!] 未找到有效URL，请检查输入\033[0m")
            return
        
        print(f"[*] 加载 {len(urls)} 个目标URL")
        
        # 使用异步IO执行探测
        asyncio.run(self._async_detect(urls))
        
        # 处理结果
        self._process_results()
        self._generate_reports()
        
        elapsed = time.time() - start_time
        print(f"\n\033[32m[+] 探测完成! 耗时: {elapsed:.2f}秒\033[0m")
        print(f"   结果保存至: {self.output_dir}")
        
        # 打印结果表格
        self._print_results_table()
    
    def _load_urls(self) -> List[str]:
        """从文件或单个URL加载URL并规范化"""
        urls = []
        seen = set()
        
        # 优先处理单个URL
        if self.single_url:
            normalized = self._normalize_url(self.single_url)
            if normalized and normalized not in seen:
                seen.add(normalized)
                urls.append(normalized)
                print(f"   目标URL: {self.single_url}")
        
        # 处理文件中的URL
        if self.input_file:
            try:
                with open(self.input_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if not url:
                            continue
                        
                        # 规范化URL
                        normalized = self._normalize_url(url)
                        if normalized and normalized not in seen:
                            seen.add(normalized)
                            urls.append(normalized)
                print(f"   目标文件: {self.input_file}")
            except Exception as e:
                print(f"\033[31m[!] 读取文件错误: {e}\033[0m")
        
        return urls
    
    def _normalize_url(self, url: str) -> str:
        """规范化URL格式"""
        if not url:
            return None
            
        if not url.startswith(('http://', 'https://')):
            # 尝试双协议探测
            return f"http://{url}"
        
        return url
    
    async def _async_detect(self, urls: List[str]):
        """异步执行站点探测"""
        connector = aiohttp.TCPConnector(limit_per_host=5, limit=self.threads)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._prepare_headers(),
            trust_env=True
        ) as session:
            tasks = []
            for url in urls:
                if self.random_delay:
                    await asyncio.sleep(random.uniform(0.1, 0.5))
                tasks.append(self._check_site(session, url))
            
            # 使用tqdm显示进度条
            if len(urls) > 1:
                from tqdm import tqdm
                for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="探测进度"):
                    await f
            else:
                await asyncio.gather(*tasks)
    
    async def _check_site(self, session: aiohttp.ClientSession, url: str):
        """检查单个站点状态"""
        result = {
            "url": url,
            "status": "未知",
            "status_code": 0,
            "content_length": 0,
            "title": "",
            "redirects": [],
            "server": "",
            "error": "",
            "screenshot": "",
            "is_alive": False,
            "is_suspicious": False,
            "final_url": url,
            "dns_resolved": False,  # DNS解析状态
            "icmp_response": False  # ICMP响应状态
        }
        
        # 解析域名并检查存活状态
        domain = self._extract_domain(url)
        if domain:
            # DNS解析检测
            result["dns_resolved"] = self._resolve_domain(domain)
            
            # ICMP检测（仅在DNS解析成功后执行）
            if result["dns_resolved"]:
                result["icmp_response"] = self._check_icmp_response(domain)
        
        # 重定向链跟踪
        redirect_history = []
        current_url = url
        
        for attempt in range(self.max_retries + 1):
            try:
                # 发送请求
                async with session.get(
                    current_url,
                    allow_redirects=False,
                    proxy=self.proxy,
                    ssl=False
                ) as response:
                    # 处理重定向
                    if response.status in (301, 302, 303, 307, 308) and self.follow_redirects:
                        redirect_url = response.headers.get('Location', '')
                        if redirect_url:
                            redirect_history.append(current_url)
                            current_url = self._resolve_redirect(current_url, redirect_url)
                            continue
                    
                    # 收集响应信息
                    content = await response.read()
                    result.update({
                        "status_code": response.status,
                        "content_length": len(content),
                        "server": response.headers.get('Server', ''),
                        "final_url": str(response.url),
                        "redirects": redirect_history
                    })
                    
                    # 提取标题
                    result["title"] = self._extract_title(content)
                    
                    # 判断存活状态
                    result.update(self._determine_alive_status(result, content))
                    
                    # 保存截图
                    if self.screenshot and result["status_code"] == 200:
                        result["screenshot"] = self._capture_screenshot(url)
                    
                    break
                
            except aiohttp.ClientConnectorError as e:
                error_type = "连接错误"
                result.update({
                    "status": "错误",
                    "error": f"{error_type}: {str(e)}",
                    "is_alive": False
                })
            except aiohttp.ServerTimeoutError as e:
                error_type = "超时错误"
                result.update({
                    "status": "错误",
                    "error": f"{error_type}: {str(e)}",
                    "is_alive": False
                })
            except Exception as e:
                error_type = type(e).__name__
                result.update({
                    "status": "错误",
                    "error": f"{error_type}: {str(e)}",
                    "is_alive": False
                })
                
            # 重试
            if attempt < self.max_retries and not result["is_alive"]:
                await asyncio.sleep(1)
            else:
                break
        
        self.results.append(result)
        return result
    
    def _extract_domain(self, url: str) -> str:
        """从URL中提取域名"""
        try:
            parsed = urlparse(url)
            return parsed.hostname
        except:
            return None
    
    def _resolve_domain(self, domain: str) -> bool:
        """解析域名是否可达"""
        try:
            socket.getaddrinfo(domain, None)
            return True
        except (socket.gaierror, socket.herror):
            return False
    
    def _check_icmp_response(self, domain: str) -> bool:
        """ICMP协议检测主机响应（跨平台优化版）"""
        try:
            # 构建跨平台ping命令
            if os.name == 'nt':  # Windows系统
                command = ['ping', '-n', '1', '-w', '1000', domain]
            else:  # Linux/macOS系统
                command = ['ping', '-c', '1', '-W', '1', domain]
            
            # 执行命令并设置整体超时
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2  # 整体超时控制（秒）
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False  # 命令执行超时
        except Exception as e:
            print(f"\033[33m[!] ICMP检测异常({domain}): {str(e)}\033[0m")
            return False

    def _prepare_headers(self) -> Dict:
        """准备请求头"""
        headers = {
            'User-Agent': random.choice(DEFAULT_USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # 添加自定义头
        if self.custom_headers:
            headers.update(self.custom_headers)
        
        return headers
    
    def _resolve_redirect(self, base_url: str, redirect_url: str) -> str:
        """解析重定向URL"""
        if not redirect_url:
            return base_url
            
        if redirect_url.startswith('http'):
            return redirect_url
            
        # 处理相对路径重定向
        try:
            return urljoin(base_url, redirect_url)
        except:
            return base_url
    
    def _extract_title(self, content: bytes) -> str:
        """从HTML内容中提取标题"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            title = soup.title.string.strip() if soup.title else ""
            return title[:100]  # 限制标题长度
        except:
            return ""
    
    def _determine_alive_status(self, result: Dict, content: bytes) -> Dict:
        """判断站点存活状态"""
        status = result["status_code"]
        is_alive = False
        is_suspicious = False
        
        if 200 <= status < 300:
            is_alive = True
        elif 300 <= status < 400:
            is_alive = True  # 重定向视为存活
        elif status == 403 or status == 401:
            is_suspicious = True
        
        # 检查是否为静态资源
        path = urlparse(result["url"]).path
        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            is_alive = False
            is_suspicious = True
        
        # 状态描述
        status_desc = "存活" if is_alive else "无效"
        if is_suspicious:
            status_desc = "疑似"
        
        return {
            "is_alive": is_alive,
            "is_suspicious": is_suspicious,
            "status": status_desc
        }
    
    def _capture_screenshot(self, url: str) -> str:
        """使用Selenium捕获网站截图"""
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument(f'user-agent={random.choice(DEFAULT_USER_AGENTS)}')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(15)
            driver.get(url)
            
            # 截取页面
            filename = f"screenshot_{int(time.time())}_{hash(url)}.png"
            save_path = os.path.join(self.screenshot_dir, filename)
            driver.save_screenshot(save_path)
            driver.quit()
            
            return save_path
        except Exception as e:
            print(f"\033[33m[!] 截图失败 ({url}): {str(e)}\033[0m")
            return ""
    
    def _process_results(self):
        """处理探测结果"""
        # 分类结果
        self.alive_urls = [r for r in self.results if r["is_alive"] and not r["is_suspicious"]]
        self.suspicious_urls = [r for r in self.results if r["is_suspicious"]]
        self.dead_urls = [r for r in self.results if not r["is_alive"]]
        
        # 打印统计信息
        print(f"\n\033[1m探测结果统计:\033[0m")
        print(f"  高置信存活: \033[32m{len(self.alive_urls)}\033[0m")
        print(f"  疑似存活: \033[33m{len(self.suspicious_urls)}\033[0m")
        print(f"  无效站点: \033[31m{len(self.dead_urls)}\033[0m")
        
        # 域名状态统计
        resolved_domains = sum(1 for r in self.results if r["dns_resolved"])
        icmp_responses = sum(1 for r in self.results if r["icmp_response"])
        print(f"\n\033[1m域名状态统计:\033[0m")
        print(f"  DNS解析成功: \033[32m{resolved_domains}/{len(self.results)}\033[0m")
        print(f"  ICMP响应: \033[32m{icmp_responses}/{len(self.results)}\033[0m")
    
    def _print_results_table(self):
        """在控制台打印结果表格"""
        if not self.results:
            print("\n\033[33m[!] 无探测结果可显示\033[0m")
            return
            
        print("\n\033[1m详细探测结果:\033[0m")
        
        # 表格头
        print(f"+{'='*124}+")
        print(f"| {'URL':<50} | {'状态码':^6} | {'标题':<20} | {'服务器':<15} | {'状态':<8} | {'DNS解析':<8} | {'ICMP响应':<8} |")
        print(f"+{'-'*124}+")
        
        # 表格内容
        for result in self.results:
            # 状态颜色
            if result["is_alive"] and not result["is_suspicious"]:
                status = "\033[32m存活\033[0m"
            elif result["is_suspicious"]:
                status = "\033[33m疑似\033[0m"
            else:
                status = "\033[31m无效\033[0m"
            
            # DNS解析状态
            dns_status = "\033[32m成功\033[0m" if result["dns_resolved"] else "\033[31m失败\033[0m"
            
            # ICMP响应状态
            icmp_status = "\033[32m响应\033[0m" if result["icmp_response"] else "\033[31m无响应\033[0m"
            
            # 完整URL显示
            url_display = result["url"]
            
            # 缩短长标题
            title_display = result["title"]
            if len(title_display) > 20:
                title_display = title_display[:17] + "..."
            
            # 服务器显示
            server_display = result["server"]
            if len(server_display) > 15:
                server_display = server_display[:12] + "..."
            
            print(f"| {url_display:<50} | {result['status_code']:^6} | {title_display:<20} | {server_display:<15} | {status:<8} | {dns_status:<8} | {icmp_status:<8} |")
        
        print(f"+{'='*124}+")
        print("\n\033[1m状态说明:\033[0m")
        print("  \033[32m存活\033[0m: HTTP状态码2xx/3xx，且非静态资源，服务可正常访问")
        print("  \033[33m疑似\033[0m: HTTP 403/401等权限错误，或静态资源被误判为服务入口")
        print("  \033[31m无效\033[0m: 连接超时、DNS解析失败或服务无响应")
        print("  \033[31m错误\033[0m: 请求过程中发生网络或协议级异常")
        print("\n状态技术说明:")
        print("  DNS解析 - 域名是否成功解析为IP地址")
        print("  ICMP响应 - 主机是否响应ping请求")
    
    def _generate_reports(self):
        """生成多种格式的报告"""
        if not self.results:
            print("\n\033[33m[!] 无探测结果，跳过报告生成\033[0m")
            return
        
        # 生成基础文件名（包含URL信息）
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if self.single_url:
            domain = urlparse(self.single_url).hostname or "single_url"
            base_filename = f"report_{domain}_{timestamp}"
        elif self.input_file:
            filename_base = os.path.splitext(os.path.basename(self.input_file))[0]
            base_filename = f"report_{filename_base}_{timestamp}"
        else:
            base_filename = f"report_{timestamp}"
        
        # 保存所有结果到JSON（默认）
        json_path = os.path.join(self.output_dir, f"{base_filename}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"[*] JSON报告已保存: {json_path}")
        
        # 根据报告格式参数生成其他报告
        if self.report_format in ["csv", "all"]:
            csv_path = os.path.join(self.output_dir, f"{base_filename}.csv")
            self._generate_csv_report(csv_path)
        
        if self.report_format in ["html", "all"]:
            html_path = os.path.join(self.output_dir, f"{base_filename}.html")
            self._generate_html_report(html_path)
        
        # 保存分类URL列表（无论报告格式如何都生成）
        self._save_url_list("alive_urls.txt", self.alive_urls)
        self._save_url_list("suspicious_urls.txt", self.suspicious_urls)
        self._save_url_list("dead_urls.txt", self.dead_urls)
    
    def _generate_csv_report(self, path: str):
        """生成CSV格式报告"""
        with open(path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'url', 'final_url', 'status', 'status_code', 'content_length', 
                'title', 'server', 'is_alive', 'is_suspicious', 'screenshot',
                'dns_resolved', 'icmp_response'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                row = {k: result.get(k, '') for k in fieldnames}
                writer.writerow(row)
        print(f"[*] CSV报告已保存: {path}")
    
    def _generate_html_report(self, path: str):
        """生成交互式HTML报告"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Web站点存活检测报告</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                .summary {{ margin-bottom: 30px; }}
                .card {{ 
                    border: 1px solid #ddd; 
                    border-radius: 5px; 
                    padding: 15px; 
                    margin-bottom: 15px; 
                    background-color: #f9f9f9;
                }}
                .alive {{ border-left: 5px solid #4CAF50; }}
                .suspicious {{ border-left: 5px solid #FFC107; }}
                .dead {{ border-left: 5px solid #F44336; }}
                .url {{ font-weight: bold; }}
                .info {{ margin-top: 5px; font-size: 0.9em; color: #666; }}
                .screenshot {{ max-width: 300px; max-height: 200px; margin-top: 10px; }}
                .status-indicator {{ 
                    display: inline-block; 
                    width: 12px; 
                    height: 12px; 
                    border-radius: 50%; 
                    margin-right: 5px;
                }}
                .alive-status {{ background-color: #4CAF50; }}
                .suspicious-status {{ background-color: #FFC107; }}
                .dead-status {{ background-color: #F44336; }}
                .dns-status {{ 
                    display: inline-block;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-size: 0.8em;
                }}
                .dns-success {{ background-color: #e8f5e9; color: #2e7d32; }}
                .dns-fail {{ background-color: #ffebee; color: #c62828; }}
                .icmp-status {{ 
                    display: inline-block;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-size: 0.8em;
                    margin-left: 10px;
                }}
                .icmp-success {{ background-color: #e3f2fd; color: #0d47a1; }}
                .icmp-fail {{ background-color: #fff8e1; color: #ff6f00; }}
                .status-explanation {{
                    margin-top: 30px;
                    padding: 15px;
                    background-color: #f5f5f5;
                    border-radius: 5px;
                }}
                .status-item {{
                    margin-bottom: 10px;
                    padding: 8px;
                    border-radius: 4px;
                }}
                .status-alive {{ 
                    background-color: #e8f5e9;
                    border-left: 3px solid #4CAF50;
                }}
                .status-suspicious {{ 
                    background-color: #fff8e1;
                    border-left: 3px solid #FFC107;
                }}
                .status-dead {{ 
                    background-color: #ffebee;
                    border-left: 3px solid #F44336;
                }}
                .status-error {{ 
                    background-color: #f5f5f5;
                    border-left: 3px solid #9E9E9E;
                }}
            </style>
        </head>
        <body>
            <h1>Web站点存活检测报告</h1>
            <div class="summary">
                <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>扫描目标: {self.input_file or self.single_url}</p>
                <p>高置信存活: <span style="color:green">{len(self.alive_urls)}</span></p>
                <p>疑似存活: <span style="color:orange">{len(self.suspicious_urls)}</span></p>
                <p>无效站点: <span style="color:red">{len(self.dead_urls)}</span></p>
            </div>
            <h2>详细结果</h2>
        """
        
        # 添加结果卡片
        for result in self.results:
            # 确定状态类
            if result["is_alive"] and not result["is_suspicious"]:
                status_class = "alive"
                status_text = "存活"
                status_indicator = "alive-status"
            elif result["is_suspicious"]:
                status_class = "suspicious"
                status_text = "疑似"
                status_indicator = "suspicious-status"
            else:
                status_class = "dead"
                status_text = "无效"
                status_indicator = "dead-status"
            
            # DNS状态
            dns_class = "dns-success" if result["dns_resolved"] else "dns-fail"
            dns_text = "DNS解析成功" if result["dns_resolved"] else "DNS解析失败"
            
            # ICMP状态
            icmp_class = "icmp-success" if result["icmp_response"] else "icmp-fail"
            icmp_text = "ICMP响应正常" if result["icmp_response"] else "ICMP无响应"
            
            screenshot_html = ""
            if result["screenshot"]:
                rel_path = os.path.relpath(result["screenshot"], os.path.dirname(path))
                screenshot_html = f'<div><img src="{rel_path}" class="screenshot" alt="Screenshot"></div>'
            
            html += f"""
            <div class="card {status_class}">
                <div class="url">{result["url"]}</div>
                <div class="info">
                    <div>
                        <span class="status-indicator {status_indicator}"></span>
                        <strong>{status_text}</strong>
                        | 状态码: {result["status_code"]} 
                        | 内容长度: {result["content_length"]} 
                        | 服务器: {result["server"]}
                    </div>
                    <div>标题: {result["title"]}</div>
                    <div>
                        <span class="dns-status {dns_class}">{dns_text}</span>
                        <span class="icmp-status {icmp_class}">{icmp_text}</span>
                    </div>
                    <div>最终URL: {result["final_url"]}</div>
                    {screenshot_html}
                </div>
            </div>
            """
        
        # 添加状态说明部分
        html += """
        <div class="status-explanation">
            <h3>状态说明</h3>
            <div class="status-item status-alive">
                <strong>存活</strong> - HTTP状态码2xx/3xx，且非静态资源，服务可正常访问
            </div>
            <div class="status-item status-suspicious">
                <strong>疑似</strong> - HTTP 403/401等权限错误，或静态资源被误判为服务入口
            </div>
            <div class="status-item status-dead">
                <strong>无效</strong> - 连接超时、DNS解析失败或服务无响应
            </div>
            <div class="status-item status-error">
                <strong>错误</strong> - 请求过程中发生网络或协议级异常
            </div>
            
            <h3>技术说明</h3>
            <p><strong>DNS解析</strong> - 域名是否成功解析为IP地址</p>
            <p><strong>ICMP响应</strong> - 主机是否响应ping请求</p>
        </div>
        """
        
        html += "</body></html>"
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[*] HTML报告已保存: {path}")
    
    def _save_url_list(self, filename: str, results: List[Dict]):
        """保存URL列表到文件"""
        if not results:
            return
            
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(result["url"] + "\n")

# ======================== 命令行接口 ========================
def parse_args():
    parser = argparse.ArgumentParser(
        description="高性能Web站点存活探测工具",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # 互斥参数：输入文件或单个URL
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input', help="包含URL列表的输入文件")
    group.add_argument('-u', '--url', help="单个目标URL")
    
    parser.add_argument('-o', '--output', default="results", help="结果输出目录")
    parser.add_argument('-t', '--threads', type=int, default=50, help="并发线程数")
    parser.add_argument('-T', '--timeout', type=int, default=10, help="请求超时时间(秒)")
    parser.add_argument('-r', '--retries', type=int, default=2, help="失败重试次数")
    parser.add_argument('-s', '--screenshot', action='store_true', help="启用网站截图功能")
    parser.add_argument('-d', '--random-delay', action='store_true', help="启用随机延迟避免检测")
    parser.add_argument('-p', '--proxy', help="使用代理服务器 (格式: http://host:port)")
    parser.add_argument('--no-redirect', action='store_true', help="不跟随重定向")
    parser.add_argument('--header', action='append', help="自定义请求头 (格式: 'Header: Value')")
    
    # 报告格式参数
    parser.add_argument('--report-format', choices=['json', 'csv', 'html', 'all'], 
                        default='json', help="指定报告输出格式: json (默认), csv, html, all")
    
    return parser.parse_args()

def main():
    
    args = parse_args()
    
    # 解析自定义头
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                key, value = h.split(':', 1)
                custom_headers[key.strip()] = value.strip()
    
    # 初始化探测器
    detector = WebDetector(
        input_file=args.input,
        single_url=args.url,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout,
        max_retries=args.retries,
        follow_redirects=not args.no_redirect,
        screenshot=args.screenshot,
        random_delay=args.random_delay,
        proxy=args.proxy,
        custom_headers=custom_headers,
        report_format=args.report_format
    )
    
    # 启动探测
    detector.run()

if __name__ == '__main__':
    main()