using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

namespace VMRCPACK.Security.Crypt
{
    public static class MD5
    {
        public static string GerateKeyFromObject(object source)
        {
            string hashString = string.Empty;
            if (source == null)
                throw new ArgumentNullException("Null as parameter is not allowed");
            else
            {
                BinaryFormatter formater = new BinaryFormatter();
                MemoryStream stream = new MemoryStream();
                try
                {
                    formater.Serialize(stream, source);
                    hashString = ComputeHash(stream.ToArray());
                    return hashString;
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    stream.Close();
                }
            }
        }

        public static string GenerateKeyFromString(string sourceString)
        {
            string hashString = string.Empty;
            if (string.IsNullOrEmpty(sourceString))
                throw new ArgumentNullException("Null as parameter is not allowed");
            else
            {
                try
                {
                    hashString = ComputeHash(System.Text.Encoding.ASCII.GetBytes(sourceString));
                    return hashString;
                }
                catch (Exception ex)
                {
                    throw new ApplicationException("Could not definitely generate key from string. Message:" + ex.Message);
                }
            }
        }

        private static string ComputeHash(byte[] objectAsBytes)
        {
            var md5 = new MD5CryptoServiceProvider();
            try
            {
                byte[] result = md5.ComputeHash(objectAsBytes);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i <= result.Length - 1; i++)
                {
                    sb.Append(result[i].ToString("X2"));
                }

                return sb.ToString();
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("Hash has not been generated.");
                return null;
            }
        }
    }
}
