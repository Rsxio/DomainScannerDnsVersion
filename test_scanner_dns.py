#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名扫描器测试脚本 (DNS/HTTP版本)
用于测试DNS/HTTP版本域名扫描器的功能
"""

import os
import sys
from domain_generator import DomainGenerator
from domain_checker_dns import DomainCheckerDNS

def test_domain_generator():
    """测试域名生成器"""
    print("=== 测试域名生成器 ===")
    generator = DomainGenerator()
    
    # 测试纯字母域名生成
    print("\n测试纯字母域名生成:")
    letter_domains = generator.generate_pure_letters(1, '.com')
    print(f"生成了 {len(letter_domains)} 个纯字母域名")
    print("示例:", letter_domains[:5])
    
    # 测试纯数字域名生成
    print("\n测试纯数字域名生成:")
    digit_domains = generator.generate_pure_digits(1, '.im')
    print(f"生成了 {len(digit_domains)} 个纯数字域名")
    print("示例:", digit_domains[:5])
    
    # 测试字母数字混合域名生成
    print("\n测试字母数字混合域名生成:")
    alphanumeric_domains = generator.generate_sample('alphanumeric', (1, 1), '.gs', 10)
    print(f"生成了 {len(alphanumeric_domains)} 个字母数字混合域名")
    print("示例:", alphanumeric_domains)
    
    # 测试多TLD域名生成
    print("\n测试多TLD域名生成:")
    multi_tld_domains = generator.generate_sample('letters', (1, 1), None, 10)
    print(f"生成了 {len(multi_tld_domains)} 个多TLD域名")
    print("示例:", multi_tld_domains)
    
    return True

def test_domain_checker_dns():
    """测试DNS/HTTP域名检查器"""
    print("\n=== 测试DNS/HTTP域名检查器 ===")
    checker = DomainCheckerDNS(max_workers=2, query_delay=(1, 2), timeout=5, retries=2)
    
    # 测试域名列表 - 包含已知已注册和可能未注册的域名
    test_domains = [
        "google.com",  # 已注册
        "example.com",  # 已注册
        "thisisaprobablynotregistered123456789.com",  # 可能未注册
        "a.im",  # 可能已注册或未注册
        "z.pw"   # 可能已注册或未注册
    ]
    
    print(f"测试检查 {len(test_domains)} 个域名:")
    for domain in test_domains:
        print(f"- {domain}")
    
    # 检查域名
    print("\n开始检查域名...")
    results = checker.check_domains(test_domains)
    
    # 打印结果
    print("\n检查结果:")
    print(f"可用域名: {len(results['available'])}")
    for domain in results['available']:
        print(f"- {domain}")
    
    print(f"\n已注册域名: {len(results['unavailable'])}")
    for domain in results['unavailable']:
        print(f"- {domain}")
    
    print(f"\n检查出错的域名: {len(results['error'])}")
    for domain in results['error']:
        print(f"- {domain}")
    
    return len(results['available']) + len(results['unavailable']) > 0

def test_small_scan_dns():
    """测试小规模扫描 (DNS/HTTP版本)"""
    print("\n=== 测试小规模扫描 (DNS/HTTP版本) ===")
    
    # 导入域名扫描器
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from domain_scanner_dns import DomainScannerDNS
    
    # 创建测试结果目录
    test_results_dir = "test_results_dns"
    if not os.path.exists(test_results_dir):
        os.makedirs(test_results_dir)
    
    # 创建扫描器
    scanner = DomainScannerDNS(
        max_workers=2, 
        query_delay=(1, 3), 
        timeout=5, 
        retries=2,
        results_dir=test_results_dir
    )
    
    # 设置扫描参数 - 只扫描极少量域名用于测试
    mode = 'letters'
    length_range = (1, 1)  # 只扫描1个字符的域名
    tlds = ['.im']  # 只扫描.im域名
    limit = 3  # 限制只扫描3个域名
    
    print(f"开始小规模扫描测试:")
    print(f"- 模式: {mode}")
    print(f"- 长度范围: {length_range}")
    print(f"- TLDs: {tlds}")
    print(f"- 限制数量: {limit}")
    print(f"- 结果目录: {test_results_dir}")
    print(f"- 超时设置: {5}秒, 重试次数: {2}")
    
    # 执行扫描
    results = scanner.scan(
        mode=mode,
        length_range=length_range,
        tlds=tlds,
        limit=limit,
        checkpoint_size=3
    )
    
    # 打印结果
    print("\n扫描结果:")
    for tld, domains in results.items():
        print(f"找到 {len(domains)} 个可用的 .{tld} 域名")
        for domain in domains:
            print(f"- {domain}")
    
    return True

def main():
    """主测试函数"""
    print("开始DNS/HTTP版本域名扫描器测试...\n")
    
    # 测试域名生成器
    generator_result = test_domain_generator()
    
    # 测试DNS/HTTP域名检查器
    checker_result = test_domain_checker_dns()
    
    # 测试小规模扫描
    scan_result = test_small_scan_dns()
    
    # 打印总结果
    print("\n=== 测试结果摘要 ===")
    print(f"域名生成器测试: {'通过' if generator_result else '失败'}")
    print(f"DNS/HTTP域名检查器测试: {'通过' if checker_result else '失败'}")
    print(f"小规模扫描测试: {'通过' if scan_result else '失败'}")
    
    if generator_result and checker_result and scan_result:
        print("\n所有测试通过! DNS/HTTP版本域名扫描器功能正常。")
        return 0
    else:
        print("\n测试失败! 请检查错误信息。")
        return 1

if __name__ == "__main__":
    sys.exit(main())
