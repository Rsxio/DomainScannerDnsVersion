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
        self.tlds = ['.im', '.pw', '.gs', '.com', '.de', '.ml']  # 支持的顶级域名
        
        # 定义保留域名规则
        self.reserved_rules = {
            '.de': {
                'starts_with_hyphen': True,  # 不能以连字符开头
                'ends_with_hyphen': True,    # 不能以连字符结尾
                'hyphen_in_3_4_pos': True,   # 不能在第3和第4位同时有连字符
                'max_length': 63,            # 最大长度
                'min_length': 1              # 最小长度
            },
            '.ml': {
                'starts_with_hyphen': True,  # 不能以连字符开头
                'ends_with_hyphen': True,    # 不能以连字符结尾
                'max_length': 63,            # 最大长度
                'min_length': 3              # 最小长度
            }
        }
    
    def generate_pure_letters(self, length, tld=None, start_chars=None):
        """
        生成纯字母域名
        
        参数:
            length (int): 域名长度（不包括TLD）
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            start_chars (str): 指定的首字母，如果为None则不限制首字母
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        tlds_to_use = [tld] if tld else self.tlds
        
        # 如果指定了首字母，则只使用这些字母作为第一个字符
        first_chars = start_chars if start_chars else self.letters
        
        # 生成所有可能的字母组合
        if length == 1:
            # 如果长度为1，直接使用首字母列表
            for first_char in first_chars:
                for tld_suffix in tlds_to_use:
                    domain = f"{first_char}{tld_suffix}"
                    if self.is_valid_domain(domain):
                        domains.append(domain)
        else:
            # 如果长度大于1，第一个字符使用首字母列表，其余字符使用所有字母
            for first_char in first_chars:
                for combo in itertools.product(self.letters, repeat=length-1):
                    domain_name = first_char + ''.join(combo)
                    for tld_suffix in tlds_to_use:
                        domain = f"{domain_name}{tld_suffix}"
                        if self.is_valid_domain(domain):
                            domains.append(domain)
        
        return domains
    
    def generate_pure_digits(self, length, tld=None, start_chars=None):
        """
        生成纯数字域名
        
        参数:
            length (int): 域名长度（不包括TLD）
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            start_chars (str): 指定的首字符，如果为None则不限制首字符
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        tlds_to_use = [tld] if tld else self.tlds
        
        # 如果指定了首字符，则只使用这些字符作为第一个字符
        # 过滤出数字字符
        valid_start_chars = ''.join([c for c in (start_chars or '') if c in self.digits])
        first_chars = valid_start_chars if valid_start_chars else self.digits
        
        # 生成所有可能的数字组合
        if length == 1:
            # 如果长度为1，直接使用首字符列表
            for first_char in first_chars:
                for tld_suffix in tlds_to_use:
                    domain = f"{first_char}{tld_suffix}"
                    if self.is_valid_domain(domain):
                        domains.append(domain)
        else:
            # 如果长度大于1，第一个字符使用首字符列表，其余字符使用所有数字
            for first_char in first_chars:
                for combo in itertools.product(self.digits, repeat=length-1):
                    domain_name = first_char + ''.join(combo)
                    for tld_suffix in tlds_to_use:
                        domain = f"{domain_name}{tld_suffix}"
                        if self.is_valid_domain(domain):
                            domains.append(domain)
        
        return domains
    
    def generate_alphanumeric(self, length, tld=None, start_chars=None):
        """
        生成字母数字混合域名
        
        参数:
            length (int): 域名长度（不包括TLD）
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            start_chars (str): 指定的首字符，如果为None则不限制首字符
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        tlds_to_use = [tld] if tld else self.tlds
        chars = self.letters + self.digits
        
        # 如果指定了首字符，则只使用这些字符作为第一个字符
        # 过滤出有效的字母和数字字符
        valid_start_chars = ''.join([c for c in (start_chars or '') if c in chars])
        first_chars = valid_start_chars if valid_start_chars else chars
        
        # 生成所有可能的字母数字组合
        if length == 1:
            # 如果长度为1，直接使用首字符列表
            for first_char in first_chars:
                for tld_suffix in tlds_to_use:
                    domain = f"{first_char}{tld_suffix}"
                    if self.is_valid_domain(domain):
                        domains.append(domain)
        else:
            # 如果长度大于1，第一个字符使用首字符列表，其余字符使用所有字母和数字
            for first_char in first_chars:
                for combo in itertools.product(chars, repeat=length-1):
                    domain_name = first_char + ''.join(combo)
                    for tld_suffix in tlds_to_use:
                        domain = f"{domain_name}{tld_suffix}"
                        if self.is_valid_domain(domain):
                            domains.append(domain)
        
        return domains
    
    def generate_domains(self, mode, length_range, tld=None, limit=None, shuffle=True, start_chars=None):
        """
        根据指定模式生成域名
        
        参数:
            mode (str): 生成模式，可选值为 'letters', 'digits', 'alphanumeric'
            length_range (tuple): 域名长度范围，如 (2, 3) 表示生成2-3个字符的域名
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            limit (int): 限制生成的域名数量，如果为None则生成所有可能组合
            shuffle (bool): 是否打乱生成的域名顺序
            start_chars (str): 指定的首字符，如果为None则不限制首字符
            
        返回:
            list: 生成的域名列表
        """
        domains = []
        min_length, max_length = length_range
        
        # 对每个长度生成域名
        for length in range(min_length, max_length + 1):
            if mode == 'letters':
                domains.extend(self.generate_pure_letters(length, tld, start_chars))
            elif mode == 'digits':
                domains.extend(self.generate_pure_digits(length, tld, start_chars))
            elif mode == 'alphanumeric':
                domains.extend(self.generate_alphanumeric(length, tld, start_chars))
            else:
                raise ValueError(f"不支持的生成模式: {mode}")
        
        # 如果需要，打乱域名顺序
        if shuffle:
            random.shuffle(domains)
        
        # 如果设置了限制，截取指定数量的域名
        if limit and len(domains) > limit:
            domains = domains[:limit]
        
        return domains
    
    def generate_sample(self, mode, length_range, tld=None, sample_size=100, start_chars=None):
        """
        生成指定数量的样本域名
        
        参数:
            mode (str): 生成模式，可选值为 'letters', 'digits', 'alphanumeric'
            length_range (tuple): 域名长度范围，如 (2, 3) 表示生成2-3个字符的域名
            tld (str): 指定的顶级域名，如果为None则使用所有支持的TLD
            sample_size (int): 样本大小
            start_chars (str): 指定的首字符，如果为None则不限制首字符
            
        返回:
            list: 生成的域名样本列表
        """
        all_domains = self.generate_domains(mode, length_range, tld, limit=None, shuffle=True, start_chars=start_chars)
        
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
    
    def is_valid_domain(self, domain):
        """
        检查域名是否有效（不是保留域名）
        
        参数:
            domain (str): 完整域名（包括后缀）
            
        返回:
            bool: 如果域名有效返回True，否则返回False
        """
        # 提取TLD
        tld = None
        for t in self.tlds:
            if domain.endswith(t):
                tld = t
                break
        
        if not tld:
            return True  # 如果不是我们支持的TLD，默认为有效
        
        # 提取域名部分（不包括TLD）
        domain_name = domain[:-len(tld)]
        
        # 检查特定TLD的规则
        if tld in self.reserved_rules:
            rules = self.reserved_rules[tld]
            
            # 检查长度
            if len(domain_name) < rules.get('min_length', 1) or len(domain_name) > rules.get('max_length', 63):
                return False
            
            # 检查是否以连字符开头
            if rules.get('starts_with_hyphen', False) and domain_name.startswith('-'):
                return False
            
            # 检查是否以连字符结尾
            if rules.get('ends_with_hyphen', False) and domain_name.endswith('-'):
                return False
            
            # 检查第3和第4位是否同时为连字符
            if rules.get('hyphen_in_3_4_pos', False) and len(domain_name) >= 4 and domain_name[2] == '-' and domain_name[3] == '-':
                return False
        
        return True


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
    
    # 测试.de域名生成
    de_domains = generator.generate_sample('letters', (2, 3), '.de', 10)
    print(f"生成了 {len(de_domains)} 个.de域名")
    print("示例:", de_domains)
    
    # 测试.ml域名生成
    ml_domains = generator.generate_sample('letters', (3, 4), '.ml', 10)
    print(f"生成了 {len(ml_domains)} 个.ml域名")
    print("示例:", ml_domains)
    
    # 测试指定首字母的域名生成
    s_domains = generator.generate_sample('letters', (3, 3), '.ml', 10, start_chars='s')
    print(f"生成了 {len(s_domains)} 个以's'开头的.ml域名")
    print("示例:", s_domains)
    
    # 测试指定多个首字母的域名生成
    ab_domains = generator.generate_sample('letters', (3, 3), '.ml', 10, start_chars='ab')
    print(f"生成了 {len(ab_domains)} 个以'a'或'b'开头的.ml域名")
    print("示例:", ab_domains)
    
    # 测试保留域名过滤
    test_domains = [
        "a.de",          # 有效
        "ab.de",         # 有效
        "-ab.de",        # 无效，以连字符开头
        "ab-.de",        # 无效，以连字符结尾
        "ab--cd.de",     # 有效，连字符不在3-4位置
        "xy--z.de",      # 无效，连字符在3-4位置
        "ab.ml",         # 无效，长度小于3
        "abc.ml",        # 有效
        "-abc.ml",       # 无效，以连字符开头
        "abc-.ml",       # 无效，以连字符结尾
    ]
    
    print("\n测试域名保留规则:")
    for domain in test_domains:
        valid = generator.is_valid_domain(domain)
        print(f"{domain}: {'有效' if valid else '无效'}")

