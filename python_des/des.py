from tools.convert_bit import hex_bin, bin_dec, dec_bin, bin_hex
from des_tables import PI, CP_1, CP_2, shift_list, EXPEND_R, S_BOX, P_table, PI_1, P, PAD
# 按块儿计算 每次计算64bit
# DES输入的规定是64bit,8字节，少于需要补充，缺几个字节就补0几
# eg. 0123456789 -> 5字节（少三） 需要补充：0123456789030303
#
# 特殊情况 011 1.5字节怎么补充
# 先补充到 0101（补位 补够一位），在补充 0101060606060606
#
# 输入就是8字节，那也必须补充填充一个分组
# 0123456789abcdef0808080808080808
#
# 明文缺少可以填充(规则pkcs#7)，密钥是不可以的必须符合要求
#
# 当明文输入大于64比特怎么办？比如100比特长：padding填充为128比特，变成倍数
#
# 模式
# ECB: 不需要iv，分块计算，每块没有关联，可以并发执行计算
# CBC: 需要iv，每块有依赖性，当前块明文初始化前需要和上一块儿加密结果进行"异或"操作，iv保证和第一次明文异或
# CFB: 需要iv，iv当做块儿计算，最终结果 明文计算 和iv的块儿计算 进行异或 => 当作明文输入加密后 和第二个明文块异或
# OFB: 需要iv, 只有iv进行了加密操作，每执行一次加密需要 和 明文块儿进行异或 得到密文块， 最后结果相加

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

def get_LR16(plaintext_bin, k16_bin_key):
      """
      2.明文的处理(l,r 代表明文左右) ln = rn-1, rn = ln-1 ^ F(rn-1, kn)
      2.1 F函数 第一步 E(R0) 和 k做异或使用EXPEND表把R0 32位 扩展到48位
      :param plaintext_bin:
      :param k16_bin_key:
      :return:
      """
      #  L0/R0
      Ln_1, Rn_1 = plaintext_bin[:len(plaintext_bin) // 2], plaintext_bin[len(plaintext_bin) // 2:]
      for key_index in range(len(k16_bin_key)):

            key = k16_bin_key[key_index]
            # 将32位明文进行扩充
            expend_right_new_bin_inpupt = "".join([Rn_1[i-1] for i in EXPEND_R])
            # print("扩充后的RightPlaintext:"+expend_right_new_bin_inpupt)
            # 2.2 E(R0) ^ k，和k做异或
            expend_right_new_bin_inpupt_P1 = "".join([P(expend_right_new_bin_inpupt[i], key[i]) for i in range(48)])
            # print("扩充后的RightPlaintext和k做异或:", expend_right_new_bin_inpupt_P1)
            # 2.3 S(E(R0) ^ k), 在S盒中找到对应的位置
            # 2.3.1 将2.2 分为八等分 B1B2.......
            B_list = [expend_right_new_bin_inpupt_P1[i: i+6] for i in range(0, 48, 6)]
            # print("E(R0) ^ k 规则分块：", B_list)
            # 2.3.2 以B1 "011000"为例子 分为两部分
            #     第一部分：第一位和最后一位 》00， 对应十进制为0，也就是第0行
            #     第二部分：中间四位 1100， 对应的十进制 为12 (index 就是list下标)， 也就是第12列
            # 在S盒中 从 0 开始数（S_BOx第0个索引开始找即 S_B0x[0]中），代表第一行第十二个 对应表中数据 5 -> 0101
            # 以B2为例子 "010001" 对应S_B0x[1]
            #     第一部分：首尾两位 "01" -> 1 确定行数
            #     第二部分：中间四位 "1000" -> 8 确定列
            #     可推出结果对应的值为 S_B0x[1][1][8] -> 12 -> 1100
            # 最后通过 8轮*4位数 S(E(R0) ^ k) 结果就变成了32位
            # print(B_list)
            from_b0x_P1 = ""
            for i in range(len(B_list)):
                  B = B_list[i]
                  row = int(bin_dec(B[0]+B[-1]))
                  col = int(bin_dec(B[1:5]))
                  B_from_S_BOX = dec_bin(S_BOX[i][row][col])
                  # print(S_BOX[i][row][col], B_from_S_BOX)
                  from_b0x_P1 +=B_from_S_BOX
            # print("通过S盒变换新生成的明文：" +from_b0x_P1)
            # 2.4 P置换，将S盒后得到的结果进行P表置换 重新排列后得到32位
            from_P = "".join([from_b0x_P1[i-1] for i in P_table])
            # print("将S盒的值进行P置换:"+from_P)
            # 2.5 最后L0 ^ f函数
            Rn = "".join([P(Ln_1[i], from_P[i]) for i in range(32)])
            Ln = Rn_1 # l1 = r0

            # 留给下一轮用
            Rn_1 = Rn
            Ln_1 = Ln
            # print(f"第 {key_index+1} 轮: R{key_index+1}>{Rn}")
            # print(f"第 {key_index+1} 轮: L{key_index+1}>{Ln}")
            # print(">"*60)

      # 3.最后获得的L16 和 R16 调换位置 并通过PI_1进行摸位置变换
      new_bin_inpupt = Rn_1+Ln_1
      result = "".join([new_bin_inpupt[i-1] for i in PI_1])
      # print(f"result: {bin_hex(result).lower()}; result:",result)
      return bin_hex(result).lower()

def init_plaintext(plaintext, iv=""):
      """
      初始化明文
      :param plaintext: type > hex
      :param iv:  type > hex
      :return:
      """
      bin_input = hex_bin(plaintext)
      if iv:
            bin_iv = hex_bin(iv)
            bin_input = "".join([P(bin_iv[i], bin_input[i]) for i in range(len(bin_iv))])

      # 初始化明文
      new_bin_inpupt = "".join([bin_input[i-1] for i in PI])
      return new_bin_inpupt

def padding_plaintext(plaintext):
      """
      对hex明文进行 padding并返回 分块列表
      :param plaintext:
      :return:
      """
      A = plaintext + PAD(plaintext)
      plaintext_list = [A[i: i+16] for i in range(0, len(A), 16)]
      return plaintext_list

def des_encrypt(plaintext, key, iv):
      """
      :param plaintext:
      :param iv:
      :return:
      """
      new_bin_input = init_plaintext(plaintext, iv=iv)
      k16_list = shift_and_arrange_bin(key)
      res = get_LR16(new_bin_input, k16_list)
      return res

def des_encrypt_method_CFB(input, key, iv):
      """
      先对iv进行加密 然后 和明文块依次异或 再加密
      由于加密流程和解密流程中被块加密器加密的数据是前一段密文，
      因此即使明文数据的长度不是加密块大小的整数倍也是不需要填充的，
      这保证了数据长度在加密前后是相同的
      :param plaintext_list:
      :param key:
      :param iv:
      :return:
      """
      plaintext_list = [input[i:i+16] for i in range(0, len(input), 16)] # 简单分组
      result = ""
      for i in plaintext_list:
            res = des_encrypt(iv, key, "")
            p1 = hex_bin(i)
            print(i, res)
            res = [P(hex_bin(res)[i], p1[i]) for i in range(len(p1))]
            iv = bin_hex("".join(res))  # 第一轮结果
            print("异或结束:", iv)
            print(">>>>>")
            result+=iv.lower()
      return result

def des_encrypt_method_ECB(plaintext_list, key, iv=""):
      """
      :param input:
      :param key:
      :param iv:
      :return:
      """
      result = ""
      for i in plaintext_list:
            res = des_encrypt(i, key, iv)
            result+=res
      return result

def des_encrypt_method_CBC(plaintext_list, key, iv):
      """

      :param input:
      :param key:
      :param iv:
      :return:
      """
      result = ""
      for i in plaintext_list:
            res = des_encrypt(i, key, iv)
            iv = res
            result += res
      return result

def des_encrypt_method_OFB(input, key, iv):
      """
      OFB 只用iv来进行加密
      每次加密完和当前明文块儿异或生成密文块
      不要求明文为 64bit的倍数
      加密密闻长度和明文一致
      :param input:
      :param key:
      :param iv:
      :return:
      """
      plaintext_list = [input[i:i + 16] for i in range(0, len(input), 16)]  # 简单分组
      result = ""
      for i in plaintext_list:
            res = des_encrypt(iv, key, "")
            p1 = hex_bin(i)
            res_xor = [P(hex_bin(res)[i], p1[i]) for i in range(len(p1))]
            r = bin_hex("".join(res_xor))  # 第一轮结果
            iv = res
            result += r.lower()
      return result

def run_encrypt(input, key, method="ECB", iv=""):
      """
      :param input: hex
      :param key: hex
      :param method: 默认ECB, 支持ECB/CBC/CFB/OFB
      :param iv: hex
      :return: hex
      """
      result = ""
      mod = len(input) % 2
      if mod != 0:  # 填充够一个字节
            input = input[:-1] + "0" + input[-1]
      plaintext_list = padding_plaintext(input)
      if method == "ECB":
            result = des_encrypt_method_ECB(plaintext_list, key, "")
      elif method == "CBC":
            result = des_encrypt_method_CBC(plaintext_list, key, iv)
      elif method == "CFB":
            result = des_encrypt_method_CFB(input, key, iv)
      elif method == "OFB":
            result = des_encrypt_method_OFB(input, key, iv)
      return result

if __name__ == '__main__':
      input = "0123456789abcdef012345"
      # input = "5dde8056f8cd4f89"
      key = "133457799bbcdff1"
      iv = "0123456789ABCDEF"
      # iv = ""
      result = run_encrypt(input, key, method="ECB", iv=iv)
      print(result)