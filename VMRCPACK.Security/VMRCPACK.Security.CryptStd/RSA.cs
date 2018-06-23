using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace VMRCPACK.Security.CryptStd
{
    public class KeyPairRSA
    {
        public string privateKey { get; set; }
        public string publicKey { get; set; }
    }

    public class RSA
    {
        private static UnicodeEncoding _encoder = new UnicodeEncoding();

        public static string Decrypt(string data, string privateKey)
        {
            var _rsa = new RSACryptoServiceProvider();
            var _dataArray = data.Split(new char[] { ',' });
            byte[] _dataByte = new byte[_dataArray.Length - 1 + 1];
            for (int _i = 0; _i <= _dataArray.Length - 1; _i++)
            {
                _dataByte[_i] = Convert.ToByte(_dataArray[_i]);
            }

            _rsa.FromXmlString(privateKey);
            var decryptedByte = _rsa.Decrypt(_dataByte, false);
            return _encoder.GetString(decryptedByte);
        }

        public static string Encrypt(string data, string publicKey)
        {
            var _rsa = new RSACryptoServiceProvider();
            _rsa.FromXmlString(publicKey);
            var _dataToEncrypt = _encoder.GetBytes(data);
            var _encryptedByteArray = _rsa.Encrypt(_dataToEncrypt, false).ToArray();
            var _length = _encryptedByteArray.Count();
            var _item = 0;
            var _sb = new StringBuilder();
            foreach (var x in _encryptedByteArray)
            {
                _item += 1;
                _sb.Append(x);
                if (_item < _length)
                {
                    _sb.Append(",");
                }
            }

            return _sb.ToString();
        }

        public static KeyPairRSA KeyGenerator()
        {
            KeyPairRSA result = new KeyPairRSA();
            CspParameters _cps = new CspParameters();
            _cps.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider _rsa = new RSACryptoServiceProvider(_cps);
            _rsa.PersistKeyInCsp = false;
            result.privateKey = _rsa.ToXmlString(true);
            result.publicKey = _rsa.ToXmlString(false);
            return result;
        }
    }
}
