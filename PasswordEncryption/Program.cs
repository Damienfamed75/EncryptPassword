using System;
using System.IO;
using System.Security.Cryptography;

namespace PasswordEncryption {
    class Program {
        [NonSerialized()] private static string password = "MyPassword123";
        static void Main(string[] args) {
            try {
                using (Aes myAes = Aes.Create()) {
                    byte[] encrypted = EncryptString(password, myAes.Key, myAes.IV);
                    string encryptedString = String.Concat(encrypted);
                    string roundTrip = DecryptString(encrypted, myAes.Key, myAes.IV);
                    Console.WriteLine($"Original: {password}\nEncrypted: {encryptedString}\nDecrypted: {roundTrip}\nKey: {String.Concat(myAes.Key)}");
                    Console.ReadKey();
                }
            } catch (Exception e) {
                Console.Write(string.Format("Error: {0}", e));
            }
        }
        static byte[] EncryptString(string plainText, byte[] key, byte[] IV) {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            using (Aes aesAlg = Aes.Create()) {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream()) {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)) {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt)) {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            System.IO.File.WriteAllText(@"C:\Users\damie\Desktop\TextFile.txt", String.Concat(encrypted) + "\n\n");
            return encrypted;
        }
        static string DecryptString(byte[] cipherText, byte[] key, byte[] IV) {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            string decryptedString = null;
            using (Aes aesAlg = Aes.Create()) {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText)) {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt)) {
                            decryptedString = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return decryptedString;
        }
    }
}
