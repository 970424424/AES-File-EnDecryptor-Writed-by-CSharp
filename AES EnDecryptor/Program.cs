using AES_EnDecryptor.Basement;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AES_EnDecryptor
{
    class Program
    {
        //This Value Cannot Be Modified !!!!
        static int _BlockSize = 16;
        static int _SkipSize { get; set; }

        static void Main(string[] args)
        {
            //Encrypt 2% of The Source File
            //If you wanna use different skip size to different files , you can append a special sign to each encrypted filename .
            //Thus , you can judge the skipsize length by analysising the special sign
            _SkipSize = _BlockSize * 49;
            Console_Init();
        }

        static void Console_Init()
        {
            Console.Clear();
            Console.WriteLine("1=======Encrypt Files");
            Console.WriteLine("2=======Decrypt Files");
            var keypress = Console.ReadLine();
            while (keypress != "1" && keypress != "2")
            {
                Console.Clear();
                Console.WriteLine("1=======Encrypt Files");
                Console.WriteLine("2=======Decrypt Files");
                keypress = Console.ReadLine();
            }
            switch (keypress)
            {
                case "1":
                    Console_Encrypt();
                    break;
                case "2":
                    Console_Decrypt();
                    break;
            }
        }

        static void Console_Encrypt()
        {
            Console.Clear();
            Console.WriteLine("Please Input Your Password ,Only Be Effective on This File: ");
            var password = Console.ReadLine();
            while (password == "")
            {
                Console.WriteLine();
                Console.WriteLine("Please Input Your Password ,Only Be Effective on This File:");
                password = Console.ReadLine();
            }
            Console.WriteLine();
            Console.WriteLine("Please Input The Filepath Where You Wanna Encrypted ：");
            var filepath = Console.ReadLine();
            while (!File.Exists(filepath))
            {
                Console.WriteLine();
                Console.WriteLine("Cannot Find This File ");
                Console.WriteLine("Please Input The Filepath Where You Wanna Encrypted ：");
                filepath = Console.ReadLine();
            }

            var savepath = Path.GetDirectoryName(filepath) + "\\" + Security.ToAESEncrypt(Path.GetFileName(filepath), password);
            EncryptFile(filepath, savepath, password);

        }

        static void EncryptFile(string source, string output, string password)
        {
            Console.Clear();
            Console.WriteLine("Begin to Enctypt File ...");
            try
            {
                using (FileStream fsr = new FileStream(source, FileMode.Open))
                {
                    using (FileStream fsw = new FileStream(output, FileMode.Create))
                    {
                        var length = fsr.Length;
                        var readsize = 0;
                        var delta = (_SkipSize + _BlockSize) * 1.0F / length;
                        var totalpercent = 0.0;

                        AES aes = new AES(AES.KeySize.Bits256, Security.GetKey(password));
                        byte[] buffer = new byte[_BlockSize];
                        byte[] newbuffer = new byte[_BlockSize];
                        readsize = fsr.Read(buffer, 0, _BlockSize);
                        while (readsize != 0)
                        {
                            //Encrypt Para
                            aes.Cipher(buffer, newbuffer);
                            fsw.Write(newbuffer, 0, readsize);
                            //Skip Para
                            buffer = new byte[_SkipSize];
                            readsize = fsr.Read(buffer, 0, _SkipSize);
                            if (readsize == 0)
                                break;
                            fsw.Write(buffer, 0, readsize);
                            //Read New Para
                            buffer = new byte[_BlockSize];
                            readsize = fsr.Read(buffer, 0, _BlockSize);
                            if (readsize == 0)
                                break;
                            totalpercent += delta;
                            Console.Clear();
                            Console.WriteLine("Begin to Enctypt File ...");
                            Console.WriteLine(totalpercent * 100 + "%");
                        }
                    }
                }
                Console.WriteLine("Encrypt Completed !");
                System.Diagnostics.Process.Start("explorer.exe ", Path.GetDirectoryName(output));
                Console.WriteLine("Press Any Key to Back to Menu");
                Console.ReadKey();
                Console_Init();
            }
            catch (Exception ex)
            {
                Console.Clear();
                Console.WriteLine("Encrypt Failed ! ErrorMessage :" + ex.Message);
                Console.WriteLine("Press Any Key to Back to Menu");
                Console.ReadKey();
                Console_Init();
            }
        }
        static void Console_Decrypt()
        {
            Console.Clear();
            Console.WriteLine("Please Input The Filepath Where You Wanna Decrypted ：");
            var filepath = Console.ReadLine();
            while (!File.Exists(filepath))
            {
                Console.WriteLine();
                Console.WriteLine("Cannot Find This File ");
                Console.WriteLine("Please Input The Filepath Where You Wanna Encrypted ：");
                filepath = Console.ReadLine();
            }

            Console.WriteLine();
            Console.WriteLine("Please Input Your Password To Decrypt This File: ");
            var password = Console.ReadLine();
            var savepath = "";
            while (true)
            {
                if(password == "")
                {
                    Console.WriteLine();
                    Console.WriteLine("Please Input Your Password To Decrypt This File: ");
                    password = Console.ReadLine();
                    continue;
                }
                else
                {
                    try
                    {
                        savepath = Path.GetDirectoryName(filepath) + "\\(new)" + Security.ToAESDecrypt(Path.GetFileName(filepath), password);
                        break;
                    }
                    catch
                    {
                        Console.WriteLine("Password Error . Please Input Your Password Again .");
                        password = Console.ReadLine();
                        continue;
                    }
                }
            }

            DecryptFile(filepath, savepath, password);

        }

        static void DecryptFile(string source, string output, string password)
        {
            Console.Clear();
            Console.WriteLine("Begin to Dectypt File ...");
            try
            {
                using (FileStream fsr = new FileStream(source, FileMode.Open))
                {
                    using (FileStream fsw = new FileStream(output, FileMode.Create))
                    {
                        var length = fsr.Length;
                        var readsize = 0;
                        var delta = (_SkipSize + _BlockSize) * 1.0F / length;
                        var totalpercent = 0.0;

                        AES aes = new AES(AES.KeySize.Bits256, Security.GetKey(password));
                        byte[] buffer = new byte[_BlockSize];
                        byte[] newbuffer = new byte[_BlockSize];
                        readsize = fsr.Read(buffer, 0, _BlockSize);
                        while (readsize != 0)
                        {
                            //Encrypt Para
                            aes.InvCipher(buffer, newbuffer);
                            fsw.Write(newbuffer, 0, readsize);
                            //Skip Para
                            buffer = new byte[_SkipSize];
                            readsize = fsr.Read(buffer, 0, _SkipSize);
                            if (readsize == 0)
                                break;
                            fsw.Write(buffer, 0, readsize);
                            //Read New Para
                            buffer = new byte[_BlockSize];
                            readsize = fsr.Read(buffer, 0, _BlockSize);
                            if (readsize == 0)
                                break;
                            totalpercent += delta;
                            Console.Clear();
                            Console.WriteLine("Begin to Dectypt File ...");
                            Console.WriteLine(totalpercent * 100 + "%");
                        }
                    }
                }
                Console.WriteLine("Dectypt Completed !");
                System.Diagnostics.Process.Start("explorer.exe ", Path.GetDirectoryName(output));
                Console.WriteLine("Press Any Key to Back to Menu");
                Console.ReadKey();
                Console_Init();
            }
            catch (Exception ex)
            {
                Console.Clear();
                Console.WriteLine("Dectypt Failed ! ErrorMessage :" + ex.Message);
                Console.WriteLine("Press Any Key to Back to Menu");
                Console.ReadKey();
                Console_Init();
            }
        }
    }
}
