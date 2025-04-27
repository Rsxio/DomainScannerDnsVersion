#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名生成器模块
用于生成不同类型的域名组合
"""

import string
import itertools
import random
from tqdm import tqdm

class DomainGenerator:
    """域名生成器类"""
    
    def __init__(self):
        """初始化域名生成器"""
        self.letters = string.ascii_lowercase  # 小写字母a-z
        self.digits = string.digits  # 数字0-9
        self.tlds = ['.im', '.pw', '.gs', '.com']  # 支持的顶级域名
    
    def generate_pure_letters(self, length, tld=None):
        """
        生成纯字母域名
        
        参数:
            length (int): 域名长度（不包括TLD）
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        tlds_to_use = [tld] if tld else self.tlds
        
        # 生成所有可能的字母组合
        for combo in itertools.product(self.letters, repeat=length):
            domain_name = ''.join(combo)
            for tld_suffix in tlds_to_use:
                domains.append(f"{domain_name}{tld_suffix}")
        
        return domains
    
    def generate_pure_digits(self, length, tld=None):
        """
        生成纯数字域名
        
        参数:
            length (int): 域名长度（不包括TLD）
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        tlds_to_use = [tld] if tld else self.tlds
        
        # 生成所有可能的数字组合
        for combo in itertools.product(self.digits, repeat=length):
            domain_name = ''.join(combo)
            for tld_suffix in tlds_to_use:
                domains.append(f"{domain_name}{tld_suffix}")
        
        return domains
    
    def generate_alphanumeric(self, length, tld=None):
        """
        生成字母数字混合域名
        
        参数:
            length (int): 域名长度（不包括TLD）
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        tlds_to_use = [tld] if tld else self.tlds
        chars = self.letters + self.digits
        
        # 生成所有可能的字母数字组合
        for combo in itertools.product(chars, repeat=length):
            domain_name = ''.join(combo)
            for tld_suffix in tlds_to_use:
                domains.append(f"{domain_name}{tld_suffix}")
        
        return domains
    
    def generate_domains(self, mode, length_range, tld=None, limit=None, shuffle=True):
        """
        根据指定模式生成域名
        
        参数:
            mode (str): 生成模式，可选值为 'letters', 'digits', 'alphanumeric'
            length_range (tuple): 域名长度范围，如 (2, 3) 表示生成2-3个字符的域名
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            limit (int): 限制生成的域名数量，如果为None则生成所有可能组合
            shuffle (bool): 是否打乱生成的域名顺序
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        min_length, max_length = length_range
        
        # 对每个长度生成域名
        for length in range(min_length, max_length + 1):
            if mode == 'letters':
                domains.extend(self.generate_pure_letters(length, tld))
            elif mode == 'digits':
                domains.extend(self.generate_pure_digits(length, tld))
            elif mode == 'alphanumeric':
                domains.extend(self.generate_alphanumeric(length, tld))
            else:
                raise ValueError(f"不支持的生成模式: {mode}")
        
        # 如果需要，打乱域名顺序
        if shuffle:
            random.shuffle(domains)
        
        # 如果设置了限制，截取指定数量的域名
        if limit and len(domains) > limit:
            domains = domains[:limit]
        
        return domains
    
    def generate_sample(self, mode, length_range, tld=None, sample_size=100):
        """
        生成指定数量的样本域名
        
        参数:
            mode (str): 生成模式，可选值为 'letters', 'digits', 'alphanumeric'
            length_range (tuple): 域名长度范围，如 (2, 3) 表示生成2-3个字符的域名
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            sample_size (int): 样本大小
            
        返回:
            list: 生成的域名样本列表
        """
        all_domains = self.generate_domains(mode, length_range, tld, limit=None, shuffle=True)
        
        # 如果生成的域名数量少于样本大小，返回所有域名
        if len(all_domains) <= sample_size:
            return all_domains
        
        # 否则随机选择指定数量的域名
        return random.sample(all_domains, sample_size)
    
    def save_domains(self, domains, filename):
        """
        将域名列表保存到文件
        
        参数:
            domains (list): 域名列表
            filename (str): 输出文件名
        """
        with open(filename, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        print(f"已将 {len(domains)} 个域名保存到 {filename}")


# 测试代码
if __name__ == "__main__":
    # 创建域名生成器实例
    generator = DomainGenerator()
    
    # 生成2个字符的纯字母域名
    letter_domains = generator.generate_pure_letters(2, '.com')
    print(f"生成了 {len(letter_domains)} 个纯字母域名")
    print("示例:", letter_domains[:5])
    
    # 生成2个字符的纯数字域名
    digit_domains = generator.generate_pure_digits(2, '.im')
    print(f"生成了 {len(digit_domains)} 个纯数字域名")
    print("示例:", digit_domains[:5])
    
    # 生成2个字符的字母数字混合域名
    alphanumeric_domains = generator.generate_alphanumeric(2, '.gs')
    print(f"生成了 {len(alphanumeric_domains)} 个字母数字混合域名")
    print("示例:", alphanumeric_domains[:5])
    
    # 使用通用方法生成域名
    sample_domains = generator.generate_sample('letters', (1, 2), '.pw', 10)
    print("样本域名:", sample_domains)
