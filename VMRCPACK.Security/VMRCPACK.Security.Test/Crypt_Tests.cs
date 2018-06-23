using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VMRCPACK.Security.CryptStd;

namespace VMRCPACK.Security.Test
{
    [TestClass]
    public class Crypt_Tests
    {
        private const string text = "0123456789... Hello world!";

        [TestMethod]
        public void Test_MD5_string()
        {
            string md5_result = MD5.GenerateKeyFromString(text);

            Assert.AreEqual("68D20BA812A2726789AF8C9475784D8B", md5_result);
        }

        [TestMethod]
        public void Test_DES()
        {
            string key = DES.KeyGerator(48);
            string crypt = DES.Operation(OperationType.Encrypt, key, text);

            Assert.AreEqual(false, string.IsNullOrEmpty(crypt));
            Assert.AreEqual(text, DES.Operation(OperationType.Decrypt, key, crypt));
        }

        [TestMethod]
        public void Test_RSA()
        {
            var pair = RSA.KeyGenerator();
            Assert.IsNotNull(pair);

            string crypt = RSA.Encrypt(text, pair.publicKey);
            Assert.AreEqual(false, string.IsNullOrEmpty(crypt));
            Assert.AreEqual(text, RSA.Decrypt(crypt, pair.privateKey));
        }
    }
}
