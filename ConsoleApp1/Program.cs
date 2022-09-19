using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    public static class Program
    {
        static void Main(string[] args)
        {
            // Text to encrypt:
            string clearText = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            // Encrypt text:
            string cipherText = AES_Encrypt(clearText);
            //string cipherText = "89285bfcd1c226242c5a983c6a02ee47e5c2d19c8bacc13843737fc6127678fd";

            Console.WriteLine($"Encrypted text: '{cipherText}'");

            // Decrypt text:
            clearText = AES_Decrypt(cipherText);

            // Result:
            Console.WriteLine($"Result: '{clearText}'");
        }
        
        static public string AES_Encrypt(string valueToEncrypt)
        {
            using (var aesManaged = Aes.Create())
            {
                SetupAes_KEY(aesManaged);
                byte[] encrypted;
                var encryptor = aesManaged.CreateEncryptor(aesManaged.Key, aesManaged.IV);

                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(valueToEncrypt);
                        }
                        encrypted = memoryStream.ToArray();
                    }
                }

                return ByteArrayToHexString(encrypted);
            }
        }

        static public string AES_Decrypt(string valueToDecrypt)
        {
            using (var aesManaged = Aes.Create())
            {
                SetupAes_KEY(aesManaged);
                var decrypted = "";
                var cipherByte = GetBytesFromHexString(valueToDecrypt).ToArray();
                var decryptor = aesManaged.CreateDecryptor(aesManaged.Key, aesManaged.IV);

                using (var memoryStream = new MemoryStream(cipherByte))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            decrypted = streamReader.ReadToEnd();
                        }
                    }
                }

                return decrypted;
            }
        }

        static private void SetupAes_KEY(Aes aesManaged)
        {
            aesManaged.KeySize = 256;
            aesManaged.Key = GetBytesFromHexString("6E95D79A283D7395527BD0123847E0DDD64A9E7A2B9D80D3C0BDF4701FBCBCB5").ToArray();
            aesManaged.IV = GetBytesFromHexString("BCFD52E66A83ACE56FBA208118E78D17").ToArray();
        }

        /// <summary>
        /// Convert byte array to hex string without separator "-".
        /// </summary>
        static public string ByteArrayToString(byte[] ba) =>
            BitConverter.ToString(ba).Replace("-", "");

        /// <summary>
        /// Convert byte array to hex string
        /// </summary>
        /// <param name="ba">Byte array to convert.</param>
        /// <returns>Returns hexadecimal string.</returns>
        static public string ByteArrayToHexString(byte[] ba) =>
            ba == null || ba.Length == 0 ? null : BitConverter.ToString(ba).Replace("-", "");

        /// <summary>
        /// Converts an hexadecimal string into byte array. The hexadecimal string contains an even
        /// number of bytes, because each 2 bytes represent a single byte in hexadecimal
        /// representation.
        /// </summary>
        /// <param name="hexadecimalString">Hexadecimal string.</param>
        /// <returns>Byte enumerable.</returns>
        static public IEnumerable<byte> GetBytesFromHexString(string hexadecimalString)
        {
            for (int index = 0; index < hexadecimalString.Length; index += 2)
            {
                yield return Convert.ToByte(hexadecimalString.Substring(index, 2), 16);
            }
        }
    }
}
