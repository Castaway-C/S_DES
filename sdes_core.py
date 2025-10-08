# 置换表和S盒定义
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # P10置换表
P8 = [6, 3, 7, 4, 8, 5, 10, 9]        # P8置换表
LeftShift1 = [2, 3, 4, 5, 1]          # 第一次左移模式
LeftShift2 = [3, 4, 5, 1, 2]          # 第二次左移模式

IP = [2, 6, 3, 1, 4, 8, 5, 7]         # 初始置换IP
IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]     # 最终置换IP⁻¹

EP = [4, 1, 2, 3, 2, 3, 4, 1]         # EP扩展盒
Sbox1 = [                             # S盒1
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2]
]
Sbox2 = [                             # S盒2
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3]
]
SP = [2, 4, 3, 1]                     # SP置换表

def permute(input_bits, permutation_table):
    return ''.join([input_bits[i-1] for i in permutation_table])

def left_shift(bits, shift_pattern):
    return ''.join([bits[i-1] for i in shift_pattern])

def generate_keys(key):
    p10_out = permute(key, P10)
    left_half, right_half = p10_out[:5], p10_out[5:]
    
    # 生成k1
    left_shifted1 = left_shift(left_half, LeftShift1)
    right_shifted1 = left_shift(right_half, LeftShift1)
    k1 = permute(left_shifted1 + right_shifted1, P8)
    
    # 生成k2
    left_shifted2 = left_shift(left_shifted1, LeftShift2)
    right_shifted2 = left_shift(right_shifted1, LeftShift2)
    k2 = permute(left_shifted2 + right_shifted2, P8)
    
    return k1, k2

def f_function(right_half, subkey):
    # EP扩展：4位 → 8位
    ep_out = permute(right_half, EP)
    
    # 与子密钥异或
    xor_out = ''.join([str(int(a) ^ int(b)) for a, b in zip(ep_out, subkey)])
    
    # 分为左右各4位，进入S盒1和S盒2
    left_sbox_in, right_sbox_in = xor_out[:4], xor_out[4:]
    
    # 处理S盒1：4位 → 2位
    row1 = int(left_sbox_in[0] + left_sbox_in[3], 2)
    col1 = int(left_sbox_in[1] + left_sbox_in[2], 2)
    s1_out = Sbox1[row1][col1]
    s1_bin = format(s1_out, '02b')
    
    # 处理S盒2：4位 → 2位
    row2 = int(right_sbox_in[0] + right_sbox_in[3], 2)
    col2 = int(right_sbox_in[1] + right_sbox_in[2], 2)
    s2_out = Sbox2[row2][col2]
    s2_bin = format(s2_out, '02b')
    
    # 合并S盒输出，再SP置换
    s_combined = s1_bin + s2_bin
    sp_out = permute(s_combined, SP)
    
    return sp_out

def encrypt(plaintext, key):
    # 初始置换IP
    ip_out = permute(plaintext, IP)
    left, right = ip_out[:4], ip_out[4:]
    
    # 获取子密钥
    k1, k2 = generate_keys(key)
    
    # 第一轮：k1
    f_out = f_function(right, k1)
    new_left = ''.join([str(int(a) ^ int(b)) for a, b in zip(left, f_out)])
    left, right = right, new_left  # 交换左右半部分
    
    # 第二轮：k2
    f_out = f_function(right, k2)
    new_left = ''.join([str(int(a) ^ int(b)) for a, b in zip(left, f_out)])
    
    # 合并左右半部分，最终置换IP⁻¹
    pre_final = new_left + right
    return permute(pre_final, IP_inv)

def decrypt(ciphertext, key):
    # 初始置换IP
    ip_out = permute(ciphertext, IP)
    left, right = ip_out[:4], ip_out[4:]
    
    # 获取子密钥
    k1, k2 = generate_keys(key)
    
    # 第一轮：k2
    f_out = f_function(right, k2)
    new_left = ''.join([str(int(a) ^ int(b)) for a, b in zip(left, f_out)])
    left, right = right, new_left
    
    # 第二轮：k1
    f_out = f_function(right, k1)
    new_left = ''.join([str(int(a) ^ int(b)) for a, b in zip(left, f_out)])
    
    # 合并左右半部分，置换IP⁻¹
    pre_final = new_left + right
    return permute(pre_final, IP_inv)
    