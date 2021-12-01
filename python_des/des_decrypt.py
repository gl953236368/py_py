from tools.convert_bit import hex_bin, bin_dec, dec_bin, bin_hex
from des import des_encrypt
from des_tables import CP_1, shift_list, CP_2, EXPEND_R, S_BOX, P_table, P, PI_1, PI

def init_ciphertext(ciphertext, iv=""):
    """
    初始化明文
    :param plaintext: type > hex
    :param iv:  type > hex
    :return:
    """
    # 还原
    plain_bin_text = ["0"] * 64  # 明文和iv异或后的值
    for i in range(64):
        plain_bin_text[PI[i] - 1] = ciphertext[i]

    if iv:
        bin_iv = hex_bin(iv)
        plain_bin_text = "".join([P(bin_iv[i], plain_bin_text[i]) for i in range(len(plain_bin_text))])

    res_from_PI = "".join(plain_bin_text)

    return bin_hex(res_from_PI)

def des_decrypt(ciphertext, key, iv):
    """

    :param ciphertext:
    :param key:
    :param iv:
    :return:
    """
    k16_list = shift_and_arrange_bin(key)
    bin_input = reverse_get_LR16(hex_bin(ciphertext), k16_list)
    plaintext = init_ciphertext(bin_input, iv)
    return plaintext

def shift_and_arrange_bin(key):
    """
    1.密钥的编排
    :param key:
    :return:
    """
    bin_key = hex_bin(key)
    # 1.1 编排密钥  分割左右 压缩 64》56 第一次对密钥进行编排 压缩
    bin_key_convert = "".join([bin_key[i - 1] for i in CP_1])
    left_bin_key, right_bin_key = bin_key_convert[:len(bin_key_convert) // 2], \
                                  bin_key_convert[len(bin_key_convert) // 2:]
    count = 0
    key_list = []
    while count < 16:
        # 1.2 分割后 对第一次的循环左移shift
        def move_left_position(bin_str, count): # 位移 bin数组
            bin_list = list(bin_str)
            while count:
                num = bin_list.pop(0)
                bin_list.append(num)
                count-=1
            return "".join(bin_list)

        left_bin_key = move_left_position(left_bin_key, shift_list[count])
        right_bin_key = move_left_position(right_bin_key, shift_list[count])
        k = left_bin_key + right_bin_key
        # 1.3 使用PC2(置换选择表2)进行置换，只有48个位置
        bin_key_convert = "".join([k[i - 1] for i in CP_2])  # 第二次对 密钥进行编排 压缩 56 》 48 生成对应的密钥之一
        key_list.append(bin_key_convert)
        # print(f"第{count + 1}次位移Left:" + left_bin_key)
        # print(f"第{count + 1}次位移Right:" + right_bin_key)
        # print(f"第{count + 1}次位移后合并密钥:" + bin_key_convert)
        count += 1
    return key_list

def reverse_get_LR16(result, k16_bin_key):
    """
    解密
    :return:
    """
    # res = hex_bin(result) # 16进制转2
    res = result
    new_res = ["0"]*64
    for i in range(64):
        new_res[PI_1[i]-1] = res[i]
    res_from_PI = "".join(new_res)  # 还原R16 L16
    # Ln = Rn-1
    Rn, Ln = res_from_PI[:len(res_from_PI) // 2], res_from_PI[len(res_from_PI) // 2:]
    for key_index in range(len(k16_bin_key)):
        key = k16_bin_key[15 - key_index] # k16开始
        expend_right_new_bin_inpupt = "".join([Ln[ i -1] for i in EXPEND_R]) # Rn-1
        expend_right_new_bin_inpupt_P1 = "".join([P(expend_right_new_bin_inpupt[i], key[i]) for i in range(48)])
        B_list = [expend_right_new_bin_inpupt_P1[i: i+ 6] for i in range(0, 48, 6)]
        from_b0x_P1 = ""
        for i in range(len(B_list)):
            B = B_list[i]
            row = int(bin_dec(B[0] + B[-1]))
            col = int(bin_dec(B[1:5]))
            B_from_S_BOX = dec_bin(S_BOX[i][row][col])
            # print(S_BOX[i][row][col], B_from_S_BOX)
            from_b0x_P1 += B_from_S_BOX
        # print("通过S盒变换新生成的明文：" +from_b0x_P1)
        # 2.4 P置换，将S盒后得到的结果进行P表置换 重新排列后得到32位
        from_P = "".join([from_b0x_P1[i - 1] for i in P_table])
        Ln_1 = "".join([P(Rn[i], from_P[i]) for i in range(32)])
        Rn_1 = Ln
    #
    #
    #     # 留给下一轮用
        Rn = Rn_1
        Ln = Ln_1
        # print(f"第 {15 - key_index} 轮: R{15 - key_index}>{Rn}")
        # print(f"第 {15 - key_index} 轮: L{15 - key_index}>{Ln}")
        # print(">" * 60)

    return Ln + Rn

def des_decrypt_method_ECB(cipher_list, key, iv):
    """
    ECB模式 块与块直接关系不大 分块计算
    :param cipher_list:
    :param key:
    :param iv:
    :return:
    """
    res = ""
    for cipher_index in range(len(cipher_list)):
        cipher_ = cipher_list[cipher_index]
        plaintext = des_decrypt(cipher_, key, iv)
        res += plaintext
    print(f"密文: {ciphertext}")
    print(f"解密结果（ECB）: {res}")
    return res

def des_decrypt_method_CBC(cipher_list, key, iv):
    """
    CBC模式 块与块儿依赖性比较强 需要从最后一块儿开始倒推
    后一块 需要上一块做iv 进行计算 解密后进行 异或 得到当前块明文
    :param cipher_list:
    :param key:
    :param iv:
    :return:
    """
    res = ""
    cipher_list.reverse()
    cipher_list.append(iv)
    for cipher_index in range(len(cipher_list)-1):
        cipher_ = cipher_list[cipher_index]
        iv = cipher_list[cipher_index+1]
        plaintext = des_decrypt(cipher_, key, iv)
        res = plaintext + res
    print(f"密文: {ciphertext}")
    print(f"解密结果（CBC）: {res}")
    return res

def des_decrypt_method_CFB(cipher_list, key, iv):
    """
    CFB模式 第一块儿明文 对iv进行加密 异或密文块儿 得到明文
    后续块儿明文 由上一块儿密文块 加密 异或下一块密文块儿 得到明文
    循环获得所有明文块儿
    :param cipher_list:
    :param key:
    :param iv:
    :return:
    """
    res = ""
    for cipher_index in range(len(cipher_list)):
        cipher_bin = hex_bin(cipher_list[cipher_index])
        iv = des_encrypt(iv, key, "") # 通过iv 加密 异或出第一段明文
        cipher_new = [P(cipher_bin[i], hex_bin(iv)[i]) for i in range(len(cipher_bin))]
        res += bin_hex("".join(cipher_new))
        iv = cipher_list[cipher_index]
    print(f"密文: {ciphertext}")
    print(f"解密结果（CFB）: {res}")
    return res

def des_decrypt_method_OFB(cipher_list, key, iv):
    """
    OFB模式解密 iv-des加密 异或对应块儿 得出对应明文块儿
    每获取一块儿 iv需要再上次基础上再加密 循环获得所有块明文
    :param cipher_list:
    :param key:
    :param iv:
    :return:
    """
    res = ""
    for cipher_index in range(len(cipher_list)):
        cipher_bin = hex_bin(cipher_list[cipher_index])
        iv = des_encrypt(iv, key, "")  # 通过iv 加密 异或出第一段明文
        cipher_new = [P(cipher_bin[i], hex_bin(iv)[i]) for i in range(len(cipher_bin))]
        res += bin_hex("".join(cipher_new))
    print(f"密文: {ciphertext}")
    print(f"解密结果（OFB）: {res}")
    return res

def run_decrypt(ciphertext, key, method="ECB", iv=""):
    """
    :param ciphertext: hex
    :param key: hex
    :param method: 默认ECB, 支持ECB/CBC/CFB/OFB
    :param iv: hex
    :return: hex
    """
    result = ""
    cipher_list = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]  # 简单分组
    if method == "ECB":
        result = des_decrypt_method_ECB(cipher_list, key, "")
    elif method == "CBC":
        result = des_decrypt_method_CBC(cipher_list, key, iv)
    elif method == "CFB":
        result = des_decrypt_method_CFB(cipher_list, key, iv)
    elif method == "OFB":
        result = des_decrypt_method_OFB(cipher_list, key, iv)
    return result


if __name__ == '__main__':
    ciphertext = "85e813540f0ab405ed83107733170631"
    key = "133457799bbcdff1"
    iv = "0123456789ABCDEF"
    result = run_decrypt(ciphertext, key, method="ECB",iv=iv)


