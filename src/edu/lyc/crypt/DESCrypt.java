package edu.lyc.crypt;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Vector;
import java.util.Collections;

import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;

public class DESCrypt {

    final static char[] IP_TABLE =
            {
                    58, 50, 42, 34, 26, 18, 10, 2,
                    60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6,
                    64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9, 1,
                    59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5,
                    63, 55, 47, 39, 31, 23, 15, 7
            };
    final static char[] IP1_TABLE =
            {

                    40, 8, 48, 16, 56, 24, 64, 32,
                    39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25
            };
    final static char[] EXTENSION_TABLE =
            {

                    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
                    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
            };
    final static char[] P_TABLE =
            {

                    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
            };
    final static char[] PC1_TABLE =
            {

                    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
            };
    final static char[] PC2_TABLE =
            {

                    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
            };
    final static char[] LOOP_TABLE =
            {
                    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
            };
    final static char[][][] S_BOX =
            {
                    {//S盒1
                            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
                    },
                    {//S盒2
                            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},

                    },
                    {//S盒3
                            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},

                    },
                    {//S盒4
                            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},

                    },
                    {//S盒5
                            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

                    },
                    {//S盒6
                            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},

                    },
                    {//S盒7
                            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},

                    },
                    {//S盒8
                            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},

                    }
            };

    /**
     * 初始置换IP
     *
     * @param ip 输入的64位明文
     * @return 按照IP_TABLE重新排序后的表
     */
    private static char[] ipTransform(char[] ip) {

        final int LENGTH = 64;//秘钥位数

        char[] result = new char[LENGTH];
        for (int i = 0; i < LENGTH; i++) {
            result[i] = ip[IP_TABLE[1] - 1];
        }
        return result;
    }

    /**
     * 秘钥置换PC-1
     *
     * @param key 初始秘钥
     * @return 经过PC-1后的 56bit
     */
    private static char[] keyPC1(char[] key) {

        final int ROUND = 56;//循环轮数

        char[] subKey = key;
        char[] result = new char[ROUND];
        for (int i = 0; i < ROUND; i++) {
            result[i] = subKey[PC1_TABLE[i] - 1];
        }
        return result;
    }

    /**
     * 子秘钥类
     */
    //public SubKey[] subKeys = new SubKey[16];//????????????

    /*public class SubKey {

        char[] subKey;//子秘钥
        int number = 0;//子秘钥序数

        private void SubKey() {
            number++;
        }
    }*/

    Vector<char[]> subKeys = new Vector<>();


    /**
     * 获取16个子秘钥
     *
     * @param subKey 初始秘钥
     */
    private void keyPC2(char[] subKey) {

        final int ROUND = 16;
        final int LEFT_RIGHT = 28;
        final int KEYBIT = 48;

        //将子秘钥分为左右两部分C0 D0
        char[] left = new char[LEFT_RIGHT];
        char[] right = new char[LEFT_RIGHT];
        for (int i = 0; i < LEFT_RIGHT; i++) {
            left[i] = subKey[i];
            right[i] = subKey[i + 28];
        }
        //生成16位子秘钥
        for (int i = 0; i < ROUND; i++) {
            try {
                left = leftRoute(left, i);
                right = leftRoute(right, i);
                char[] together = new char[LEFT_RIGHT * 2];
                //together = (left.toString() + right.toString()).toCharArray();//PROBLEM
                for (int j = 0; j < LEFT_RIGHT; j++) {
                    together[j] = left[j];
                    together[j + LEFT_RIGHT] = right[j];
                }
                char[] result = new char[KEYBIT];
                for (int j = 0; j < KEYBIT; j++) {
                    result[j] = together[PC2_TABLE[j] - 1];
                }
                subKeys.add(result);
            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("错误发生于生成子秘钥第" + i + "轮");
            }
        }
    }

    /**
     * 循环左移
     *
     * @param cd    CX DX
     * @param round X轮
     * @return 左移后结果
     * @throws Exception 输入数据错误
     */
    private static char[] leftRoute(char[] cd, int round) throws Exception {
        char[] result = new char[cd.length];
        if (cd.length != 28) {
            throw new Exception("cd 长度有误，请检查leftRoute函数及其实现位置!");
        } else if (round > 16) {
            throw new Exception("round 长度有误，请检查leftRoute函数及其实现位置！");
        }
        try {
            if (LOOP_TABLE[round] == 1) {
                for (int i = 1; i < cd.length; i++) {
                    result[i - 1] = cd[i];
                }
                result[cd.length - 1] = cd[0];
                return result;
            } else if (LOOP_TABLE[round] == 2) {
                for (int i = 2; i < cd.length; i++) {
                    result[i - 2] = cd[i];
                }
                result[cd.length - 2] = cd[0];
                result[cd.length - 1] = cd[1];
                return result;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        System.err.println("循环左移出错，请检查leftRoute函数及其实现位置！");
        return null;
    }

    /**
     * 密码函数f
     *
     * @param startData 32位数据
     * @param round     循环轮数
     *                  也使用了秘钥类里第round轮的秘钥
     * @return
     */
    private char[] crypt_F(char[] startData, int round) {

        final int DATA = 48;
        final int SECTION = 8;
        final int SECTION_BIT = 6;
        final int SBOX_DATA = 32;
        final int PBOX_DATA = 32;

        //扩展置换
        char[] extensionData = new char[DATA];
        for (int i = 0; i < DATA; i++) {
            extensionData[i] = startData[EXTENSION_TABLE[i] - 1];
        }

        //异或运算
        char[] XorData = new char[DATA];
        XorData = Xor(extensionData, subKeys.get(round));

        //S盒运算
        //分成8个6位块
        char[][] sBoxInPut = new char[SECTION][SECTION_BIT];
        int num = 0;
        for (int i = 0; i < SECTION; i++) {
            for (int j = 0; j < SECTION_BIT; j++) {
                sBoxInPut[i][j] = XorData[num];
                num++;
            }
        }
        //S盒运算
        char[] sBoxOutPut = new char[SBOX_DATA];
        num = 0;
        //TODO 算法存疑点
        for (int i = 0; i < SECTION; i++) {
            try {
                //经过S盒算出行列值并将S盒对应数据存入intResult中
                int row = sBoxInPut[i][0] ^ sBoxInPut[i][5];
                int column = sBoxInPut[i][1] * 8 + sBoxInPut[i][2] * 4 + sBoxInPut[i][3] * 2 + sBoxInPut[i][4];
                int intResult = S_BOX[i][row][column];

                //NEW
                //将intResult中数字转化为二进制字符串
                String binResult = Integer.toBinaryString(intResult);
                //将binResult补齐为4位
                binResult = addZeroForNum(binResult, 4);
                //存入sBoxOutPut中
                sBoxOutPut[num] = (char) ((int) binResult.charAt(0) - 48);
                sBoxOutPut[num + 1] = (char) ((int) binResult.charAt(1) - 48);
                sBoxOutPut[num + 2] = (char) ((int) binResult.charAt(2) - 48);
                sBoxOutPut[num + 3] = (char) ((int) binResult.charAt(3) - 48);
                num += 4;

                //END NEW
/*
                byte[] byteResult = intToByte(intResult);
                if (byteResult.length != 4) {
                    System.err.println("SBOX位循环出错，请检查TODO算法存疑点！");
                }

                sBoxOutPut[num] = (char) byteToInt(byteResult[0]);
                sBoxOutPut[num + 1] = (char) byteToInt(byteResult[1]);
                sBoxOutPut[num + 2] = (char) byteToInt(byteResult[2]);
                sBoxOutPut[num + 3] = (char) byteToInt(byteResult[3]);
                num += 4;
                */
            } catch (ArrayIndexOutOfBoundsException e) {
                e.printStackTrace();
                System.err.println("column超限，发生在第round=" + round);
            }
        }
        if (num != 32) {
            System.err.println("sBoxOutPut位数不正确，循环次数为：" + num);
        }

        //P盒置换
        char[] pBoxOutPut = new char[PBOX_DATA];
        for (int i = 0; i < PBOX_DATA; i++) {
            pBoxOutPut[i] = sBoxOutPut[P_TABLE[i] - 1];
        }
        return pBoxOutPut;
    }

    /**
     * 尾置换IP-1
     *
     * @param left
     * @param right
     * @return 64位密文
     */
    private char[] finalIPTransform(char[] left, char[] right) {

        final int DATA_BIT = 64;

        char[] IPinput = new char[DATA_BIT];
        //IPinput = (left.toString() + right.toString()).toCharArray();
        for (int i = 0; i < DATA_BIT / 2; i++) {
            IPinput[i] = left[i];
            IPinput[i + DATA_BIT / 2] = right[i];
        }
        char[] IPoutput = new char[DATA_BIT];
        for (int i = 0; i < DATA_BIT; i++) {
            IPoutput[i] = IPinput[IP1_TABLE[i] - 1];
        }
        return IPinput;
    }

    /**
     * 异或运算方法
     *
     * @param a
     * @param b
     * @return
     */
    private char[] Xor(char[] a, char[] b) {
        char[] result = new char[a.length];
        int temp;
        if (a.length != b.length) {
            System.err.println("异或运算左右两边长度不同！请检查Xor函数及其调用的参数");
            return null;
        }
        for (int i = 0; i < a.length; i++) {
            temp = ((int) a[i]) ^ ((int) b[i]);
            result[i] = (char) temp;
        }
        return result;
    }


    /**
     * 加解密模式选择
     */
    enum crypt_mode {ENCRYPT_MODE, DECRYPT_MODE}

    enum paraCoding {BASE64, NOBASE64}

    /**
     * 执行函数接口,注意未对输入数据进行padding
     *
     * @param plainText  输入待加密明文，当解密时该变量为带解密密文，均会进行PKCS5Padding
     * @param keys       输入秘钥，并进行PKCS5Padding
     * @param codeOption 为BASE64时 对结果进行BASE64编码
     * @return
     */
    public String doFinal(crypt_mode mode, String plainText, String keys, paraCoding codeOption) {

        final int SECTION = 8;
        final int CHAR_SECTION = 64;

        if (codeOption == paraCoding.BASE64 && mode == crypt_mode.DECRYPT_MODE) {
            plainText = deBase64(plainText);
        }

        if (mode == crypt_mode.ENCRYPT_MODE) {
            try {
                plainText = PKCS5Padding.padding(plainText);
                keys = PKCS5Padding.padding(keys);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        } else if (mode == crypt_mode.DECRYPT_MODE) {
            try {
                //plainText = PKCS5Padding.dePadding(plainText);
                keys = PKCS5Padding.padding(keys);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        /*
        输出为64位二进制数，解密时不再进行明文操作直接将64位二进制数存入vecText中
         */
        Vector<char[]> vecText = new Vector<>();//每64位存入一个vector的项中
        if (mode == crypt_mode.ENCRYPT_MODE) {
            //明文操作
            byte[] bytePlainText = plainText.getBytes();//将完整明文转化为二进制

            int num = 0;//截取长度计数
            byte[] section = new byte[SECTION + 1];//每个section是byte[8] 64位

            char[] charSection = new char[CHAR_SECTION];//存结果，64位二进制数
            String stringSection = new String();//存中间结果64位二进制数

            while (num < bytePlainText.length) {
                stringSection = "";
                System.arraycopy(bytePlainText, num, section, 0, SECTION);//将全文二进制数每byte[8] 64位 存入一个section,section[8]组成64位
                num += SECTION;

                for (int i = 0; i < SECTION; i++) {
                    byte tByte = section[i];//将前8位提取
                    stringSection += Integer.toBinaryString((tByte & 0xFF) + 0x100).substring(1);//将前8位以二进制01存入String中
                }

                charSection = stringSection.toCharArray();//结果存入char[]
                for (int i = 0; i < CHAR_SECTION; i++) {
                    charSection[i] = (char) ((int) charSection[i] - 48);
                }
                vecText.add(charSection);//储存进vector
            }
        } else if (mode == crypt_mode.DECRYPT_MODE) {
            int num = 0;//截取长度计数
            while (num < plainText.length()) {
                char[] byteText = plainText.toCharArray();
                for (int i = 0; i < byteText.length; i++) {
                    byteText[i] = (char) ((int) byteText[i] - 48);
                }
                char[] charSection = new char[64];
                System.arraycopy(byteText, num, charSection, 0, 64);//每次存入64位二进制数
                num += 64;
                vecText.add(charSection);
            }
        }
        //秘钥操作
        String keysSection = new String();
        byte[] keyByte = keys.getBytes();//keyByte[8]应当有8个
        /*if (keyByte.length%8 != 8) {
            System.err.println("秘钥长度有误！请检查输入的秘钥是否正好为64位!");
        }*/
        for (int i = 0; i < SECTION; i++) {
            byte tByte = keyByte[i];
            keysSection += Integer.toBinaryString((tByte & 0xFF) + 0x100).substring(1);//将秘钥转化为二进制并存进字符串
        }
        char[] key = keysSection.toCharArray();//key内存有64位秘钥
        for (int i = 0; i < CHAR_SECTION; i++) {
            key[i] = (char) ((int) key[i] - 48);
        }

        //生成16个子秘钥

        //秘钥置换PC-1
        char[] key_PC1 = keyPC1(key);
        //得到16个子秘钥
        keyPC2(key_PC1);

        //解密秘钥变换,将16个子秘钥顺序颠倒
        if (mode == crypt_mode.DECRYPT_MODE) {
            Collections.reverse(subKeys);
        }

        Vector<char[]> result = new Vector<>();//储存结果
        //此循环遍历vector，最大循环
        for (int generalRound = 0; generalRound < vecText.size(); generalRound++) {

            final int LRBIT = 32;
            final int LRRound = 15;

            char[] charPlainText = vecText.get(generalRound);
            String middleResult = new String();

            //初始置换
            middleResult = ipTransform(charPlainText).toString();

            //拆分为L和R
            char[] left = new char[LRBIT];
            char[] right = new char[LRBIT];
            for (int i = 0; i < LRBIT; i++) {
                left[i] = charPlainText[i];
                right[i] = charPlainText[i + LRBIT];
            }

            //前15轮迭代
            for (int i = 0; i < LRRound; i++) {
                char[] leftN = left;
                left = right;
                right = Xor(leftN, crypt_F(right, i));
            }
            //第16轮迭代
            left = Xor(left, crypt_F(right, 15));

            //尾置换IP-1
            char[] finalIPTrans = finalIPTransform(left, right);

            result.add(finalIPTrans);
        }
        //提取密文二进制数据
        String binResult = new String();
        for (char[] s : result) {

            char[] sc = new char[64];
            for (int i = 0; i < 64; i++) {
                sc[i] = (char) ((int) s[i] + 48);
            }
            String binString = new String(sc);//sc或s
            binResult += binString;
        }


        //BASE64编码
        if (codeOption == paraCoding.BASE64 && mode == crypt_mode.ENCRYPT_MODE) {
            return enBase64(binResult.getBytes());
        }
        if (mode == crypt_mode.DECRYPT_MODE) {
            String regex = "(.{8})";
            binResult = binResult.replaceAll(regex,"$1 ");
            binResult = binToString(binResult);
            binResult = PKCS5Padding.dePadding(binResult);
        }

        return binResult;
        //return finalResult;
    }

    /**
     * int转化为byte[]
     *
     * @param num
     * @return
     */
    private byte[] intToByte(int num) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) ((num >> 24) & 0xff);
        bytes[1] = (byte) ((num >> 16) & 0xff);
        bytes[2] = (byte) ((num >> 8) & 0xff);
        bytes[3] = (byte) (num & 0xff);
        return bytes;
    }

    /**
     * byte数组转int类型的对象
     *
     * @param bytes
     * @return
     */
    private int byteToInt(Byte bytes) {
        return (bytes & 0xff);
    }

    /**
     * 将二进制码转换成字符串
     *
     * @param bin 二进制码
     * @return
     */
    private static String binToString(String bin) {
        String[] tempStr = bin.split(" ");
        char[] tempChar = new char[tempStr.length];
        for (int i = 0; i < tempStr.length; i++) {
            tempChar[i] = BinstrToChar(tempStr[i]);
        }
        return String.valueOf(tempChar);
    }

    /**
     * 将二进制字符串转换成int数组
     *
     * @param binStr
     * @return
     */
    private static char BinstrToChar(String binStr) {
        int[] temp = BinstrToIntArray(binStr);
        int sum = 0;
        for (int i = 0; i < temp.length; i++) {
            sum += temp[temp.length - 1 - i] << i;
        }
        return (char) sum;
    }

    /**
     * 将二进制转换成字符
     *
     * @param binStr
     * @return
     */
    private static int[] BinstrToIntArray(String binStr) {
        char[] temp = binStr.toCharArray();
        int[] result = new int[temp.length];
        for (int i = 0; i < temp.length; i++) {
            result[i] = temp[i] - 48;
        }
        return result;
    }

    private static String addZeroForNum(String str, int strLength) {
        int strLen = str.length();
        StringBuffer sb = null;
        while (strLen < strLength) {
            sb = new StringBuffer();
            sb.append("0").append(str);// 左补0
            // sb.append(str).append("0");//右补0
            str = sb.toString();
            strLen = str.length();
        }
        return str;
    }

    /**
     * BASE64加密函数
     *
     * @param text 明文待加密
     * @return String类型密文
     */
    private static String enBase64(byte[] text) {
        //byte[] content = text.getBytes();
        //System.out.println("Before enBASE64: " + text);
        return new BASE64Encoder().encode(text);
    }

    /**
     * BASE64解密函数
     *
     * @param text 待解密密文
     * @return String类明文
     */
    public static String deBase64(String text) {
        try {
            BASE64Decoder decoder = new BASE64Decoder();
            byte[] content = decoder.decodeBuffer(text);
            String result = new String(content);
            //System.out.println("After deBASE64: " + result.getBytes());
            return result;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
