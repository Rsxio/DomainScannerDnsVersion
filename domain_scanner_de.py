#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名扫描器主程序 (DENIC WHOIS版本)
用于扫描未注册的域名，特别优化了.de域名的检查
"""

import os
import time
import argparse
import concurrent.futures
from datetime import datetime
from tqdm import tqdm

# 导入自定义模块
from domain_generator import DomainGenerator
from domain_checker_dns import DomainCheckerDNS
from domain_checker_de import DomainCheckerDE

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='域名扫描器 - 扫描未注册的域名')
    
    # 域名生成参数
    parser.add_argument('--mode', choices=['letters', 'digits', 'alphanumeric'], default='letters',
                        help='域名生成模式: letters=纯字母, digits=纯数字, alphanumeric=字母数字混合')
    parser.add_argument('--min-length', type=int, default=2, help='域名最小长度（不包括后缀）')
    parser.add_argument('--max-length', type=int, default=3, help='域名最大长度（不包括后缀）')
    parser.add_argument('--tlds', nargs='+', default=['.im', '.pw', '.gs', '.com', '.de'],
                        help='要扫描的顶级域名列表，例如: .com .net .org')
    parser.add_argument('--limit', type=int, default=None, help='每个TLD生成的域名数量限制')
    
    # 域名检查参数
    parser.add_argument('--workers', type=int, default=3, help='并发工作线程数')
    parser.add_argument('--delay-min', type=float, default=1.0, help='查询延迟最小值（秒）')
    parser.add_argument('--delay-max', type=float, default=3.0, help='查询延迟最大值（秒）')
    parser.add_argument('--timeout', type=int, default=5, help='查询超时时间（秒）')
    parser.add_argument('--retries', type=int, default=2, help='查询失败时的重试次数')
    
    # 结果保存参数
    parser.add_argument('--results-dir', type=str, default='results_dns', help='结果保存目录')
    parser.add_argument('--checkpoint-size', type=int, default=10, help='每次保存检查点的域名数量')
    
    return parser.parse_args()

def ensure_dir(directory):
    """确保目录存在，如果不存在则创建"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def save_results(results, filename):
    """保存结果到文件"""
    with open(filename, 'w') as f:
        for domain in results:
            f.write(f"{domain}\n")

def main():
    """主函数"""
    args = parse_arguments()
    
    # 确保结果目录存在
    ensure_dir(args.results_dir)
    
    # 创建域名生成器
    generator = DomainGenerator()
    
    # 为每个TLD扫描域名
    for tld in args.tlds:
        print(f"\n开始扫描 {tld} 域名...")
        
        # 生成域名
        domains = generator.generate_domains(
            mode=args.mode,
            min_length=args.min_length,
            max_length=args.max_length,
            tld=tld,
            limit=args.limit
        )
        print(f"生成了 {len(domains)} 个 {tld} 域名")
        
        # 如果没有生成域名，跳过当前TLD
        if not domains:
            continue
        
        # 创建域名检查器
        if tld == '.de':
            # 对.de域名使用专门的检查器
            checker = DomainCheckerDE(
                max_workers=args.workers,
                query_delay=(args.delay_min, args.delay_max),
                timeout=args.timeout,
                retries=args.retries
            )
        else:
            # 对其他域名使用DNS检查器
            checker = DomainCheckerDNS(
                max_workers=args.workers,
                query_delay=(args.delay_min, args.delay_max),
                timeout=args.timeout,
                retries=args.retries
            )
        
        # 检查域名
        total_domains = len(domains)
        batch_size = min(1000, total_domains)  # 每批最多处理1000个域名
        
        # 准备结果文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mode_str = args.mode
        length_str = f"{args.min_length}-{args.max_length}"
        tld_str = tld.replace('.', '')
        
        available_file = os.path.join(args.results_dir, f"available_{tld_str}_{mode_str}_{length_str}_{timestamp}.txt")
        unavailable_file = os.path.join(args.results_dir, f"unavailable_{tld_str}_{mode_str}_{length_str}_{timestamp}.txt")
        error_file = os.path.join(args.results_dir, f"error_{tld_str}_{mode_str}_{length_str}_{timestamp}.txt")
        
        # 初始化结果列表
        all_available = []
        all_unavailable = []
        all_error = []
        
        # 分批处理域名
        for i in range(0, total_domains, batch_size):
            batch_end = min(i + batch_size, total_domains)
            batch = domains[i:batch_end]
            
            print(f"检查第 {i+1}-{batch_end} 个域名 (共 {total_domains} 个)")
            
            # 检查当前批次的域名
            results = checker.check_domains(batch)
            
            # 累加结果
            all_available.extend(results['available'])
            all_unavailable.extend(results['unavailable'])
            all_error.extend(results['error'])
            
            # 保存检查点
            if len(all_available) >= args.checkpoint_size:
                save_results(all_available, available_file)
                print(f"已保存 {len(all_available)} 个可用域名到 {available_file}")
                all_available = []
            
            if len(all_unavailable) >= args.checkpoint_size:
                save_results(all_unavailable, unavailable_file)
                all_unavailable = []
            
            if len(all_error) >= args.checkpoint_size:
                save_results(all_error, error_file)
                all_error = []
        
        # 保存剩余结果
        if all_available:
            save_results(all_available, available_file)
            print(f"已保存 {len(all_available)} 个可用域名到 {available_file}")
        
        if all_unavailable:
            save_results(all_unavailable, unavailable_file)
        
        if all_error:
            save_results(all_error, error_file)
    
    print("\n扫描完成！结果已保存到 " + args.results_dir + " 目录")

if __name__ == "__main__":
    main()
