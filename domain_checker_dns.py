#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名可用性检查模块 (DNS/HTTP方法)
使用DNS查询和HTTP请求检查域名是否已被注册，不依赖WHOIS服务
"""

import socket
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('domain_checker_dns')

class DomainCheckerDNS:
    """域名可用性检查类 (DNS/HTTP方法)"""
    
    def __init__(self, max_workers=3, query_delay=(2, 5), timeout=5, retries=2, use_emoji=True):
        """
        初始化域名检查器
        
        参数:
            max_workers (int): 最大并发工作线程数
            query_delay (tuple): 查询间隔时间范围(最小值, 最大值)，单位为秒
            timeout (int): DNS/HTTP查询超时时间（秒）
            retries (int): 查询失败时的重试次数
            use_emoji (bool): 是否在日志输出中使用emoji
        """
        self.max_workers = max_workers
        self.query_delay = query_delay
        self.timeout = timeout
        self.retries = retries
        self.use_emoji = use_emoji
        self.available_domains = []
        self.unavailable_domains = []
        self.error_domains = []
        
        # emoji字典
        self.emojis = {
            'check': '🔍',
            'available': '✅',
            'unavailable': '❌',
            'error': '⚠️',
            'retry': '🔄',
            'complete': '🎉'
        }
        
        # 设置socket默认超时时间
        socket.setdefaulttimeout(self.timeout)
        
        # 尝试导入requests库，用于HTTP检查
        try:
            import requests
            self.requests_available = True
        except ImportError:
            logger.warning(f"{self._emoji('error')}requests库未安装，将只使用DNS方法检查域名")
            self.requests_available = False
    
    def _emoji(self, key):
        """获取emoji，如果不使用emoji则返回空字符串"""
        if not self.use_emoji:
            return ''
        return self.emojis.get(key, '') + ' '
    
    def is_available(self, domain):
        """
        检查单个域名是否可用（未注册）
        
        参数:
            domain (str): 要检查的完整域名（包括后缀）
            
        返回:
            bool: 如果域名未注册返回True，否则返回False
            None: 如果检查过程中出现错误
        """
        for attempt in range(self.retries):
            try:
                # 添加随机延迟，避免请求过于频繁
                delay = random.uniform(self.query_delay[0], self.query_delay[1])
                time.sleep(delay)
                
                # 方法1: 使用DNS查询
                dns_result = self.check_domain_dns(domain)
                
                # 如果DNS查询表明域名未注册，再使用HTTP方法确认
                if dns_result is True and self.requests_available:
                    http_result = self.check_domain_http(domain)
                    if http_result is not None:  # 如果HTTP检查成功完成
                        return http_result
                
                # 返回DNS查询结果
                return dns_result
                
            except Exception as e:
                if attempt < self.retries - 1:
                    logger.warning(f"{self._emoji('retry')}检查域名 {domain} 时出错: {str(e)}，正在重试 ({attempt+1}/{self.retries})...")
                    # 增加延迟时间，避免频繁重试
                    time.sleep(delay * 2)
                    continue
                else:
                    logger.error(f"{self._emoji('error')}检查域名 {domain} 失败: {str(e)}")
                    return None
    
    def check_domains(self, domains, show_progress=True):
        """
        批量检查多个域名的可用性
        
        参数:
            domains (list): 要检查的域名列表
            show_progress (bool): 是否显示进度条
            
        返回:
            dict: 包含可用、不可用和错误域名的字典
        """
        self.available_domains = []
        self.unavailable_domains = []
        self.error_domains = []
        
        # 使用线程池并发检查域名
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            if show_progress:
                results = list(tqdm(executor.map(self.is_available, domains), 
                                   total=len(domains), 
                                   desc=f"{self._emoji('check')}检查域名"))
            else:
                results = list(executor.map(self.is_available, domains))
        
        # 处理结果
        for domain, result in zip(domains, results):
            if result is True:
                self.available_domains.append(domain)
            elif result is False:
                self.unavailable_domains.append(domain)
            else:
                self.error_domains.append(domain)
        
        # 打印结果摘要
        logger.info(f"{self._emoji('complete')}检查完成: 共 {len(domains)} 个域名")
        logger.info(f"{self._emoji('available')}可用域名: {len(self.available_domains)} 个")
        logger.info(f"{self._emoji('unavailable')}已注册域名: {len(self.unavailable_domains)} 个")
        logger.info(f"{self._emoji('error')}检查出错: {len(self.error_domains)} 个")
        
        return {
            'available': self.available_domains,
            'unavailable': self.unavailable_domains,
            'error': self.error_domains
        }
    
    def save_results(self, filename="available_domains.txt"):
        """
        保存可用域名到文件
        
        参数:
            filename (str): 输出文件名
        """
        with open(filename, 'w') as f:
            for domain in self.available_domains:
                f.write(f"{domain}\n")
        
        logger.info(f"{self._emoji('available')}已将 {len(self.available_domains)} 个可用域名保存到 {filename}")

    def check_domain_dns(self, domain):
        """
        使用DNS查询检查域名是否可用
        
        参数:
            domain (str): 要检查的完整域名（包括后缀）
            
        返回:
            bool: 如果域名未注册返回True，否则返回False
            None: 如果检查过程中出现错误
        """
        try:
            # 尝试解析域名
            socket.gethostbyname(domain)
            # 如果能解析，说明域名已注册
            logger.debug(f"{self._emoji('unavailable')}DNS查询结果: {domain} 已注册")
            return False
        except socket.gaierror:
            # 无法解析，可能未注册
            logger.debug(f"{self._emoji('available')}DNS查询结果: {domain} 可能未注册")
            return True
        except Exception as e:
            # 其他错误
            logger.error(f"{self._emoji('error')}DNS查询出错: {domain}, 错误: {str(e)}")
            return None

    def check_domain_http(self, domain):
        """
        使用HTTP请求检查域名是否可用
        
        参数:
            domain (str): 要检查的完整域名（包括后缀）
            
        返回:
            bool: 如果域名未注册返回True，否则返回False
            None: 如果检查过程中出现错误
        """
        if not self.requests_available:
            return None
            
        try:
            import requests
            # 设置较短的超时时间
            response = requests.head(f"http://{domain}", timeout=self.timeout)
            # 如果能访问，说明域名已注册
            logger.debug(f"{self._emoji('unavailable')}HTTP请求结果: {domain} 已注册")
            return False
        except requests.exceptions.ConnectionError:
            # 连接错误，可能未注册
            logger.debug(f"{self._emoji('available')}HTTP请求结果: {domain} 可能未注册")
            return True
        except Exception as e:
            # 其他错误，返回None表示无法确定
            logger.debug(f"{self._emoji('error')}HTTP请求出错: {domain}, 错误: {str(e)}")
            return None


# 测试代码
if __name__ == "__main__":
    # 创建域名检查器实例
    checker = DomainCheckerDNS(max_workers=2, query_delay=(1, 3), timeout=5, retries=2)
    
    # 测试域名列表
    test_domains = [
        "example.com",
        "thisisaprobablynotregistered123456789.com",
        "google.com",
        "test123.im",
        "test123.ml"
    ]
    
    # 检查域名
    results = checker.check_domains(test_domains)
    
    # 打印结果
    print(f"\n{checker._emoji('available')}可用域名:")
    for domain in results['available']:
        print(f"- {domain}")
    
    print(f"\n{checker._emoji('unavailable')}已注册域名:")
    for domain in results['unavailable']:
        print(f"- {domain}")
    
    print(f"\n{checker._emoji('error')}检查出错的域名:")
    for domain in results['error']:
        print(f"- {domain}")

