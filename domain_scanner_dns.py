#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名扫描器主程序 (DNS/HTTP版本)
集成域名生成器和DNS/HTTP域名检查器，用于扫描未注册的域名
支持.im、.pw、.gs、.com和.de域名，并过滤.de的保留域名
"""

import os
import argparse
import time
from datetime import datetime
from tqdm import tqdm

from domain_generator import DomainGenerator
from domain_checker_dns import DomainCheckerDNS

class DomainScannerDNS:
    """域名扫描器类 (DNS/HTTP版本)"""
    
    def __init__(self, max_workers=3, query_delay=(2, 5), timeout=5, retries=2, results_dir="results_dns"):
        """
        初始化域名扫描器
        
        参数:
            max_workers (int): 最大并发工作线程数
            query_delay (tuple): 查询间隔时间范围(最小值, 最大值)，单位为秒
            timeout (int): DNS/HTTP查询超时时间（秒）
            retries (int): 查询失败时的重试次数
            results_dir (str): 结果保存目录
        """
        self.generator = DomainGenerator()
        self.checker = DomainCheckerDNS(
            max_workers=max_workers, 
            query_delay=query_delay,
            timeout=timeout,
            retries=retries
        )
        self.results_dir = results_dir
        
        # 确保结果目录存在
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def scan(self, mode, length_range, tlds=None, limit=None, checkpoint_size=50):
        """
        扫描未注册的域名
        
        参数:
            mode (str): 生成模式，可选值为 'letters', 'digits', 'alphanumeric'
            length_range (tuple): 域名长度范围，如 (2, 3) 表示生成2-3个字符的域名
            tlds (list): 要扫描的顶级域名列表，如果为None则使用所有支持的TLD
            limit (int): 限制生成的域名数量
            checkpoint_size (int): 每次检查的域名数量，用于分批处理
            
        返回:
            dict: 包含可用域名的字典，按TLD分类
        """
        # 确定要使用的TLD
        tlds_to_use = tlds if tlds else self.generator.tlds
        
        # 创建结果字典
        results = {tld.replace('.', ''): [] for tld in tlds_to_use}
        
        # 为每个TLD生成并检查域名
        for tld in tlds_to_use:
            print(f"\n开始扫描 {tld} 域名...")
            
            # 生成域名
            domains = self.generator.generate_domains(mode, length_range, tld, limit)
            total_domains = len(domains)
            print(f"生成了 {total_domains} 个 {tld} 域名")
            
            # 分批检查域名
            available_domains = []
            for i in range(0, total_domains, checkpoint_size):
                batch = domains[i:i+checkpoint_size]
                print(f"检查第 {i+1}-{min(i+checkpoint_size, total_domains)} 个域名 (共 {total_domains} 个)")
                
                # 检查当前批次的域名
                check_results = self.checker.check_domains(batch)
                available_domains.extend(check_results['available'])
                
                # 保存检查点
                self._save_checkpoint(available_domains, tld, mode, length_range)
                
                # 保存错误域名，以便后续重试
                if check_results['error']:
                    self._save_error_domains(check_results['error'], tld, mode, length_range)
            
            # 将结果添加到结果字典
            results[tld.replace('.', '')] = available_domains
            
            # 保存最终结果
            self._save_results(available_domains, tld, mode, length_range)
        
        return results
    
    def _save_checkpoint(self, domains, tld, mode, length_range):
        """保存检查点"""
        min_len, max_len = length_range
        checkpoint_file = os.path.join(
            self.results_dir, 
            f"checkpoint_{tld.replace('.', '')}_{mode}_{min_len}-{max_len}.txt"
        )
        
        with open(checkpoint_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
    
    def _save_error_domains(self, domains, tld, mode, length_range):
        """保存检查出错的域名"""
        min_len, max_len = length_range
        error_file = os.path.join(
            self.results_dir, 
            f"error_{tld.replace('.', '')}_{mode}_{min_len}-{max_len}.txt"
        )
        
        with open(error_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        print(f"已将 {len(domains)} 个检查出错的 {tld} 域名保存到 {error_file}")
    
    def _save_results(self, domains, tld, mode, length_range):
        """保存最终结果"""
        min_len, max_len = length_range
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(
            self.results_dir, 
            f"available_{tld.replace('.', '')}_{mode}_{min_len}-{max_len}_{timestamp}.txt"
        )
        
        with open(result_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        print(f"已将 {len(domains)} 个可用的 {tld} 域名保存到 {result_file}")


def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="域名扫描器 (DNS/HTTP版本) - 扫描未注册的域名")
    
    parser.add_argument("--mode", choices=["letters", "digits", "alphanumeric"], default="letters",
                        help="域名生成模式: 纯字母, 纯数字, 或字母数字混合")
    
    parser.add_argument("--min-length", type=int, default=2,
                        help="域名最小长度 (不包括TLD)")
    
    parser.add_argument("--max-length", type=int, default=3,
                        help="域名最大长度 (不包括TLD)")
    
    parser.add_argument("--tlds", nargs="+", default=[".im", ".pw", ".gs", ".com", ".de"],
                        help="要扫描的顶级域名列表")
    
    parser.add_argument("--limit", type=int, default=None,
                        help="限制每个TLD生成的域名数量")
    
    parser.add_argument("--workers", type=int, default=3,
                        help="并发工作线程数")
    
    parser.add_argument("--delay-min", type=float, default=2.0,
                        help="查询延迟最小值 (秒)")
    
    parser.add_argument("--delay-max", type=float, default=5.0,
                        help="查询延迟最大值 (秒)")
    
    parser.add_argument("--timeout", type=int, default=5,
                        help="DNS/HTTP查询超时时间 (秒)")
    
    parser.add_argument("--retries", type=int, default=2,
                        help="查询失败时的重试次数")
    
    parser.add_argument("--checkpoint-size", type=int, default=50,
                        help="每次检查点的域名数量")
    
    parser.add_argument("--results-dir", default="results_dns",
                        help="结果保存目录")
    
    args = parser.parse_args()
    
    # 创建域名扫描器
    scanner = DomainScannerDNS(
        max_workers=args.workers,
        query_delay=(args.delay_min, args.delay_max),
        timeout=args.timeout,
        retries=args.retries,
        results_dir=args.results_dir
    )
    
    # 开始扫描
    print(f"开始扫描模式为 '{args.mode}' 的域名，长度范围: {args.min_length}-{args.max_length}")
    print(f"扫描的TLD: {', '.join(args.tlds)}")
    print(f"结果将保存到: {args.results_dir}")
    print(f"DNS/HTTP查询设置: 超时={args.timeout}秒, 重试次数={args.retries}, 并发线程数={args.workers}")
    
    start_time = time.time()
    results = scanner.scan(
        mode=args.mode,
        length_range=(args.min_length, args.max_length),
        tlds=args.tlds,
        limit=args.limit,
        checkpoint_size=args.checkpoint_size
    )
    end_time = time.time()
    
    # 打印结果摘要
    print("\n扫描完成!")
    print(f"总耗时: {end_time - start_time:.2f} 秒")
    
    for tld, domains in results.items():
        print(f"找到 {len(domains)} 个可用的 .{tld} 域名")


if __name__ == "__main__":
    main()
