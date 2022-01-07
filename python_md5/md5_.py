# md5
## MD5_Init 初始化
## MD5_Update 添加参数，也就是要加密的值
## MD5_Final 获取结果
import binascii
import struct
from enum import Enum
from math import floor, sin

from bitarray._bitarray import bitarray


def parse_code(strs):
    try:
        c = lambda a: [a[i:i + 2] for i in range(0, len(a), 2)][::-1]
        res = "".join(c(str(strs)[2:]))
        return binascii.unhexlify(res)
    except Exception as e:
        return ""

class MD5IvBuffer(Enum):
    # md5 标准魔值
    # 有些魔改md5加密 可能是只改了部分魔值
    A = 0x67452301  # dec. 1732584193
    B = 0xEFCDAB89  # dec. 4023233417
    C = 0x98BADCFE  # dec. 2562383102
    D = 0x10325476  # dec. 271733878

class MD5():
    _string = None
    _buffers = {
        MD5IvBuffer.A: None,
        MD5IvBuffer.B: None,
        MD5IvBuffer.C: None,
        MD5IvBuffer.D: None,
    }

    @classmethod
    def step1_plaintext(cls):
        """
        padding 操作 填充
        * 引入大小端序:
        #         大端**(Big Endian)** ：是指低地址存放，最高有效字节（MSB）。（高位放低有效值）
        #         小端**(Little Endian)** ：是低地址存放，最低有效字节（LSB）。(高位地址放高有效值)
        #         大小端转换 对应对8bit逆向 字节位置不变
        :return:
        """

        # 把字符串转成byte数组 大端
        bit_array = bitarray(endian="big")
        bit_array.frombytes(cls._string.encode("utf-8"))
        # 默认添加1（以1开始后边可能补0）, 然后保证输入字符长度 与448模512同余 不满足则补0
        bit_array.append(1)
        while len(bit_array) % 512 != 448:
            bit_array.append(0)
        # md5中都是以小端 表示 ，转为小端显示
        l_bit_array = bitarray(bit_array, endian="little")
        return l_bit_array

    @classmethod
    def step2_plaintext(cls, b_string):
        """
        由于最终要参与运算的明文长度应为 512*n，对处理后的明文（512*(n-1) + 448）位,
        # 剩余64位填充为原来消息的长度（二进制）
        #  若是原来消息的长度大于64位（2的64次方）
        #  eg.如原消息的长度为70位（2的70次方），则忽略高6位的数据，只填充低64位（即长度L mod 2的64次方）
        :param b_string:
        :return:
        """

        length = (len(cls._string) * 8) % pow(2, 64)
        length_bit_array = bitarray(endian="little")
        length_bit_array.frombytes(struct.pack("<Q", length))
        # * struct.pack python以c数据处理 二进制字节流
        #   【网络字节序定义】：收到的第一个字节被当作高位看待，这就要求发送端发送的第一个字节应当是高位。
        #   而在发送端发送数据时，发送的第一个字节是该数字在内存中起始地址对应的字节。
        #   可见多字节数值在发送前，在内存中数值应该以大端法存放。 网络字节序说是大端字节序。
        #   Q 数据类型为 unsigned long long（c）/ long （python） 数据块为 8
        #   < 表示小端 > 表示大端
        #   struct.pack("<Q", length) 将整型 length 转为 二进制

        # 拼接完成
        bit_plaintext = b_string.copy()
        bit_plaintext.extend(length_bit_array)
        return bit_plaintext

    @classmethod
    def step3_iv(cls):
        """
        初始化iv
        :return:
        """
        for buffer_type in cls._buffers.keys():
            cls._buffers[buffer_type] = buffer_type.value

    @classmethod
    def step4_cal(cls, bit_plaintext):
        """
        核心计算
        :param bit_plaintext:
        :return:
        """
        # 参与计算的方法
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & z) | (y & ~z)
        H = lambda x, y, z: x ^ y ^ z
        I = lambda x, y, z: y ^ (x | ~z)

        # T表 64个32bit数  2**32 * （sin i 的绝对值） 的整数的16进制数
        T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]

        # 加运算 防止溢出
        modular_add = lambda a, b: (a + b) % pow(2, 32)
        # 位移运算
        rotate_left = lambda x, n: (x << n) | (x >> (32 - n))

        #  1.1 初始化iv
        #  1.2 分组 按照 每 512bit 进行分块计算 划分为 16组 每组 32bit
        #   获得 n * 16 组
        N = len(bit_plaintext) // 32

        for group_index in range(N // 16):
            # 按顺序第一组 512bit
            group_start = group_index * 512
            # 每 32bit（4字节）为一个子分组 对后续 16x4 次计算划分值
            X_ = [bit_plaintext[group_start + (x * 32): group_start + (x * 32) + 32] for x in range(16)]
            # 将划分的子分组由 小端二进制转为 十进制数 16个
            X = [int.from_bytes(k.tobytes(), byteorder="little") for k in X_]

            # 引入4个iv 每个进行 16次计算
            A = cls._buffers[MD5IvBuffer.A]
            B = cls._buffers[MD5IvBuffer.B]
            C = cls._buffers[MD5IvBuffer.C]
            D = cls._buffers[MD5IvBuffer.D]
            # 1.3.1 计算iv
            # 每次循环后 A/B/C/D iv 会产生变换 =》A1=D/ B1=B+位移(A+Func(B,C,D)+明文块+Ki，S)/ C1=D/ D1=B/
            # Func为非线性函数 每16次替换
            for t in range(4 * 16):  # k代表明文块位置、t代表需要参与运算的T表位置、s代表需要参与位移的运算的值
                if 0 <= t <= 15:
                    k = t
                    s = [7, 12, 17, 22]
                    tmp = F(B, C, D)
                elif 16 <= t <= 31:
                    k = ((5 * t) + 1) % 16
                    s = [5, 9, 14, 20]
                    tmp = G(B, C, D)
                elif 32 <= t <= 47:
                    k = ((3 * t) + 5) % 16
                    s = [4, 11, 16, 23]
                    tmp = H(B, C, D)
                elif 48 <= t <= 63:
                    k = (7 * t) % 16
                    s = [6, 10, 15, 21]
                    tmp = I(B, C, D)

                print("--------------------------------------")
                print("经过F/G/H/I以及明文:", hex(tmp), parse_code(hex(X[k])), X_[k], k)

                # B的生成
                # B.1 A+F(B,C,D) =>  生成结果 0xffffffff(固定，可作为逆向切入点)
                tmp = modular_add(tmp, A)
                print("加A:", hex(tmp), hex(A))

                # B.2 A+F(B,C,D)+ X[k] =》上部分结果加 处理后的明文块
                tmp = modular_add(tmp, X[k])
                print("加明文:", hex(tmp), hex(X[k]))

                # B.3 A+F(B,C,D)+X[k]+ T[t] => 上部分结果加 T表的值（这部分一般都是固定的，魔改很少会改这块）
                tmp = modular_add(tmp, T[t])
                print("加K值:", hex(tmp), hex(T[t]))

                # B.4 移位(A+F(B,C,D)+X[k]+ T[t]，s) =》 上部分结果 进行位移操作
                tmp = rotate_left(tmp, s[t % 4])
                print("位移后:", hex(tmp))

                # B.5 B + 移位(A+F(B,C,D)+X[k]+ T[t]，s) => 上部分结果和原来的B进行相加
                tmp = modular_add(tmp, B)
                print("生成的B:", hex(tmp))

                # 互相替换 A1=D/ B1=B+位移(A+Func(B,C,D)+明文块+Ki，S)/ C1=D/ D1=B/
                A = D
                D = C
                C = B
                B = tmp
                print("新一轮IV：",hex(A), hex(B), hex(C), hex(D))

            # 1.4 对进行计算的iv 最后和每个对应的原始 iv进行相加
            cls._buffers[MD5IvBuffer.A] = modular_add(cls._buffers[MD5IvBuffer.A], A)
            cls._buffers[MD5IvBuffer.B] = modular_add(cls._buffers[MD5IvBuffer.B], B)
            cls._buffers[MD5IvBuffer.C] = modular_add(cls._buffers[MD5IvBuffer.C], C)
            cls._buffers[MD5IvBuffer.D] = modular_add(cls._buffers[MD5IvBuffer.D], D)

            # 2.结束 端序转变 输出
            # 由于是通过 小端十进制（4字节16进制数）进行相加 最后需要转变回来
            # struct.pack(">I", fin_A) 转为大端 I表示四个字节的int类型
            # 进行解包转变为十进制数 最后通过 16进制数输出 得到最终结果
            fin_A = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5IvBuffer.A]))[0]
            fin_B = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5IvBuffer.B]))[0]
            fin_C = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5IvBuffer.C]))[0]
            fin_D = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5IvBuffer.D]))[0]
            # print(f"{format(fin_A, '08x')}{format(fin_B, '08x')}{format(fin_C, '08x')}{format(fin_D, '08x')}")
            res = "{:08x}{:08x}{:08x}{:08x}".format(fin_A, fin_B, fin_C, fin_D)
            # print(res)
            return res

    @classmethod
    def hash(cls, string):
        """
        :param string:
        :return:
        """
        cls._string = string
        b_plaintext = cls.step1_plaintext() # 对明文字符串 转化 为bit 且进行 端序转化
        preprocessed_bit_array = cls.step2_plaintext(b_plaintext) # 补充64bit的 长度 使之成为 n*512
        cls.step3_iv() # 初始化iv 魔值
        res = cls.step4_cal(preprocessed_bit_array) # 计算
        return res

if __name__ == '__main__':
    res = MD5.hash("123345")
    print("结果:", res)
