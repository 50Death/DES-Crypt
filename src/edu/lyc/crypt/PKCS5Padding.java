package edu.lyc.crypt;

import java.io.UnsupportedEncodingException;

public class PKCS5Padding extends DESCrypt {
    /**
     * PKCS5Padding 添加算法
     *
     * @param text 输入
     * @return 64位的倍数的String
     * @throws UnsupportedEncodingException
     */
    public static String padding(String text) throws UnsupportedEncodingException {
        int length = text.getBytes("UTF-8").length;
        switch (length % 8) {
            case 0:
                for (int i = 0; i < 8; i++) {
                    text += 0x08;
                }
                break;
            case 1:
                for (int i = 0; i < 7; i++) {
                    text += 0x07;
                }
                break;
            case 2:
                for (int i = 0; i < 6; i++) {
                    text += 0x06;
                }
                break;
            case 3:
                for (int i = 0; i < 5; i++) {
                    text += 0x05;
                }
                break;
            case 4:
                for (int i = 0; i < 4; i++) {
                    text += 0x04;
                }
                break;
            case 5:
                for (int i = 0; i < 3; i++) {
                    text += 0x03;
                }
                break;
            case 6:
                for (int i = 0; i < 2; i++) {
                    text += 0x02;
                }
                break;
            case 7:
                text += 0x01;
                break;
        }
        return text;
    }

    /**
     * 去PKCS5Padding
     *
     * @param text 待去字符串
     * @return 去掉第一次添加
     */
    public static String dePadding(String text) {
        int length = text.length();
        String result = new String();
        char judge = text.charAt(length - 1);
        switch (judge) {
            case '8':
                if (text.substring(length - 8, length).equals("88888888")) {
                    result = text.substring(0, length - 8);
                }
                break;
            case '7':
                if (text.substring(length - 7, length).equals("7777777")) {
                    result = text.substring(0, length - 7);
                }
                break;
            case '6':
                if (text.substring(length - 6, length).equals("666666")) {
                    result = text.substring(0, length - 6);
                }
                break;
            case '5':
                if (text.substring(length - 5, length).equals("55555")) {
                    result = text.substring(0, length - 5);
                }
                break;
            case '4':
                if (text.substring(length - 4, length).equals("4444")) {
                    result = text.substring(0, length - 4);
                }
                break;
            case '3':
                if (text.substring(length - 3, length).equals("333")) {
                    result = text.substring(0, length - 3);
                }
                break;
            case '2':
                if (text.substring(length - 2, length).equals("22")) {
                    result = text.substring(0, length - 2);
                }
                break;
            case '1':
                if(text.substring(length - 1, length).equals("1"))
                result = text.substring(0, length - 1);
                break;
            default:
                result = text;
        }
        return result;
    }
}
