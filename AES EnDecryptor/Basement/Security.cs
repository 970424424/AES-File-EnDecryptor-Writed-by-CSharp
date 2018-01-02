/**
/**
 * -----创建--------------------
 * Author：Zeoun
 * CreatedBy：2018/1/2 Tuesday 8:28:24
 * Description：
 * */

using System;
using System.Collections.Generic;

using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AES_EnDecryptor.Basement
{
    public class Security
    {
        public static byte[] IV
        {
            get
            {
                return new byte[] { 0x21, 0x35, 0x51, 0x7B, 0x90, 0xCD, 0x1A, 0xDF, 0x2C, 0x15, 0x12, 0x97, 0x9A, 0xA2, 0x7C, 0xD7 };
            }
        }

        private static byte[] Key
        {
            get
            {
                return new byte[] { 0x01, 0x53, 0x25, 0x07, 0x91, 0x11, 0x77, 0x19, 0x61, 0x36, 0x54, 0xA7, 0xB9, 0x16, 0x56, 0x0A, 0x08, 0x53, 0x25, 0x0F, 0x91, 0x1F, 0x78, 0xD9, 0x62, 0x3A, 0x5D, 0xF7, 0x19, 0x15, 0x56, 0x04 };
            }
        }

        public static byte[] GetKey(string key)
        {
            byte[] myKey = new byte[16];
            if (string.IsNullOrEmpty(key))
            {
                return Key;
            }
            byte[] tmpkey = ASCIIEncoding.ASCII.GetBytes(key);
            for (int i = 0; i < 16; i++)
            {
                if (tmpkey.Length > i)
                {
                    myKey[i] = tmpkey[i];
                }
                else
                {
                    myKey[i] = Key[i];
                }
            }
            return myKey;
        }

        public static string ToAESEncrypt(string words, string key)
        {
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(words);
            RijndaelManaged rDel = new RijndaelManaged();
            rDel.Key = GetKey(key);
            rDel.IV = IV;
            rDel.Mode = CipherMode.ECB;
            rDel.Padding = PaddingMode.PKCS7;
            ICryptoTransform cTransform = rDel.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            string str = Convert.ToBase64String(resultArray, 0, resultArray.Length);
            str = str.Replace("/", "$");
            str = str.Replace("//", "%");
            return str;
        }
        public static string ToAESDecrypt(string words, string key)
        {
            words = words.Replace("$", "/");
            words = words.Replace("%", "//");
            byte[] toEncryptArray = Convert.FromBase64String(words);
            RijndaelManaged rDel = new RijndaelManaged();
            rDel.Key = GetKey(key);
            rDel.IV = IV;
            rDel.Mode = CipherMode.ECB;
            rDel.Padding = PaddingMode.PKCS7;
            ICryptoTransform cTransform = rDel.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            return UTF8Encoding.UTF8.GetString(resultArray);
        }
    }
}
