from itertools import product
import time
import tkinter as tk

def brute_force_crack(mode, plaintext, ciphertext, result_text, progress_callback):
    start_time = time.time()
    possible_keys = []
    total_keys = 1024  # 2^10 = 1024种可能的密钥
    completed = True  # 标记是否正常完成
    
    # 根据模式导入所需函数
    if mode == "ascii":
        from ascii_processor import encrypt_ascii
    else:  # binary
        from sdes_core import encrypt
    
    # 遍历所有可能的10位密钥
    try:
        for i, bits in enumerate(product('01', repeat=10)):
            # 更新进度
            progress = (i / total_keys) * 100
            progress_callback(progress)
            
            key = ''.join(bits)
            
            # 根据模式进行加密验证
            try:
                if mode == "ascii":
                    # ASCII模式：加密整个字符串并比较
                    encrypted = encrypt_ascii(plaintext, key)
                    if encrypted == ciphertext:
                        possible_keys.append(key)
                        result_text.insert(tk.END, f"找到可能的密钥: {key}\n")
                        result_text.see(tk.END)
                else:
                    # 二进制模式：加密8位数据并比较
                    encrypted = encrypt(plaintext, key)
                    if encrypted == ciphertext:
                        possible_keys.append(key)
                        result_text.insert(tk.END, f"找到可能的密钥: {key}\n")
                        result_text.see(tk.END)
            except Exception as e:
                result_text.insert(tk.END, f"处理密钥 {key} 时出错: {str(e)}\n")
                result_text.see(tk.END)
                continue
            
            # 定期更新进度信息
            if i % 100 == 0 and i > 0:
                result_text.insert(tk.END, f"已尝试 {i}/{total_keys} 个密钥...\n")
                result_text.see(tk.END)
                
    except KeyboardInterrupt:
        result_text.insert(tk.END, "\n破解被用户中断\n")
        completed = False
    except Exception as e:
        result_text.insert(tk.END, f"\n破解过程中发生错误: {str(e)}\n")
        completed = False
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    if completed:
        result_text.insert(tk.END, f"\n破解完成，耗时: {elapsed_time:.6f}秒\n")
        if len(possible_keys) == 0:
            result_text.insert(tk.END, "未能找到匹配的密钥，请检查输入数据是否正确\n")
        else:
            result_text.insert(tk.END, f"共找到 {len(possible_keys)} 个可能的密钥\n")
            
            # 验证找到的密钥
            if possible_keys:
                result_text.insert(tk.END, "\n密钥验证:\n")
                for key in possible_keys:
                    if mode == "ascii":
                       solution = encrypt_ascii(plaintext, key)
                    else:
                        solution = encrypt(plaintext, key)
                    result_text.insert(tk.END, f"密钥 {key}: 加密结果 = {solution} ({'正确' if solution == ciphertext else '错误'})\n")
    else:
        result_text.insert(tk.END, f"\n破解未正常完成，已耗时: {elapsed_time:.6f}秒\n")
    
    result_text.see(tk.END)