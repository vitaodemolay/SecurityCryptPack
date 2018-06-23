using System;

namespace VMRCPACK.Security.CryptStd
{
    public enum OperationType : byte
    {
        Encrypt = 1,
        Decrypt = 2
    }
    public static class DES
    {

        private static string Decrypt(string text, System.Security.Cryptography.TripleDESCryptoServiceProvider Des)
        {
            System.Security.Cryptography.ICryptoTransform desdencrypt = Des.CreateDecryptor();
            byte[] buff = Convert.FromBase64String(text);
            return System.Text.ASCIIEncoding.ASCII.GetString(desdencrypt.TransformFinalBlock(buff, 0, buff.Length));
        }

        private static string Encrypt(string text, System.Security.Cryptography.TripleDESCryptoServiceProvider Des)
        {
            System.Security.Cryptography.ICryptoTransform desdencrypt = Des.CreateEncryptor();
            dynamic MyASCIIEncoding = new System.Text.ASCIIEncoding();
            byte[] buff = System.Text.ASCIIEncoding.ASCII.GetBytes(text);
            return Convert.ToBase64String(desdencrypt.TransformFinalBlock(buff, 0, buff.Length));
        }

        public static string Operation(OperationType type, string Key, string text)
        {
            string _result = null;
            System.Security.Cryptography.MD5CryptoServiceProvider hashMD5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
            System.Security.Cryptography.TripleDESCryptoServiceProvider des = new System.Security.Cryptography.TripleDESCryptoServiceProvider();
            des.Key = hashMD5.ComputeHash(System.Text.ASCIIEncoding.ASCII.GetBytes(Key));
            des.Mode = System.Security.Cryptography.CipherMode.ECB;
            if ((type == OperationType.Encrypt))
                _result = Encrypt(text, des);
            else
                _result = Decrypt(text, des);

            return _result;
        }


        private static string codeGenerator(int size, bool numbers, bool letters = false, bool specialCharacters = false)
        {
            string code = "";
            string letras = "abcdefghijklmnopqrstuvwxyz";
            string numeros = "0123456789";
            string characters = "!@#$%^&*+-=";
            string charactersToSearch = "";

            if (numbers)
                charactersToSearch += numeros;
            if (letters)
                charactersToSearch += letras + letras.ToUpper();
            if (specialCharacters)
                charactersToSearch += characters;

            var randomIndex = new Random();

            for (int index = 1; index <= size; index++)
            {
                int indexToGet = randomIndex.Next(0, charactersToSearch.Length);
                code += charactersToSearch.Substring(indexToGet, 1);
            }

            return code;
        }

        public static string KeyGerator(int size)
        {
            return codeGenerator(size, true, true, true);
        }
    }
}
