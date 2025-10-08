from itertools import product
import time
import tkinter as tk
from sdes_core import encrypt


def closed_test(plaintext, result_text, progress_callback):

    start_time = time.time()

    # 初始化数据结构
    ciphertext_to_keys = {}
    total_keys = 1024  # 2^10

    # 显示初始信息
    result_text.insert(tk.END, f"开始对固定明文 '{plaintext}' 进行密钥碰撞分析...\n")
    result_text.insert(tk.END, f"将使用全部 {total_keys} 个密钥进行加密测试。\n\n")
    result_text.see(tk.END)

    try:
        # 遍历所有可能的10位密钥
        for i, bits in enumerate(product('01', repeat=10)):
            key = ''.join(bits)

            # 使用当前密钥加密明文
            ciphertext = encrypt(plaintext, key)

            if ciphertext not in ciphertext_to_keys:
                ciphertext_to_keys[ciphertext] = []
            ciphertext_to_keys[ciphertext].append(key)

            # 每处理10个密钥更新一次进度条
            if (i + 1) % 10 == 0:
                progress = ((i + 1) / total_keys) * 100
                progress_callback(progress)

        # 分析并显示结果
        result_text.insert(tk.END, "所有密钥测试完毕。分析碰撞结果如下：\n\n")

        collisions_found = 0

        for ciphertext, keys in ciphertext_to_keys.items():
            if len(keys) > 1:
                collisions_found += 1
                result_text.insert(tk.END, f"密文: {ciphertext}\n")
                result_text.insert(tk.END, f"  -> 由 {len(keys)} 个不同的密钥生成:\n")
                for key in keys:
                    result_text.insert(tk.END, f"     - {key}\n")
                result_text.insert(tk.END, "\n")
                result_text.see(tk.END)

        end_time = time.time()
        elapsed_time = end_time - start_time

        result_text.insert(tk.END, "-------------------------------------------\n")
        if collisions_found == 0:
            result_text.insert(tk.END, f"分析完成：对于明文'{plaintext}'，未发现任何密钥碰撞。\n")
        else:
            result_text.insert(tk.END, f"分析完成：共发现 {collisions_found} 组密钥碰撞。\n")
        result_text.insert(tk.END, f"总耗时: {elapsed_time:.4f} 秒\n")

    except Exception as e:
        result_text.insert(tk.END, f"\n分析过程中发生严重错误: {str(e)}\n")

    finally:
        progress_callback(100)
        result_text.see(tk.END)