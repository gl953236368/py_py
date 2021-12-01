
base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'),ord('A')+6)]

# 二进制转十进制：int(str,n=10)
def bin_dec(str_num):
    return str(int(str_num, 2))

# 十六进制转十进制
def hex_dec(str_num):
    return str(int(str_num.upper(), 16))

# 十进制转二进制字符串
def dec_bin(str_num):
    num = int(str_num)
    if num == 0:
        return "0" * 4
    mid = []
    while True:
        if num == 0:break
        num, rem = divmod(num, 2)
        mid.append(base[rem])
    res = ''.join([str(x) for x in mid[::-1]])
    return res if len(res)%4 == 0 else "0" * (4 - len(res)%4) + res

# dec2hex
# 十进制 to 八进制: oct()
# 十进制 to 十六进制: hex()
def dec_hex(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num,rem = divmod(num, 16)
        mid.append(base[rem])
    return ''.join([str(x) for x in mid[::-1]])

# 十六进制 to 二进制: bin(int(str,16))
def hex_bin(str_num):
    res = ""
    if str_num[0] == "0":
        res = "0"*4
    return res + dec_bin(hex_dec(str_num.upper()))

# 二进制 to 十六进制: hex(int(str,2))
def bin_hex(str_num):
    tmp = ""
    if len(str_num) > 3 and  "0000" == str_num[0:4]: # 解决首位为0的问题
        tmp = "0"
    return tmp + dec_hex(bin_dec(str_num))


# print(hex_bin("1"))
# print(hex_bin("0123456789abcdef"))
