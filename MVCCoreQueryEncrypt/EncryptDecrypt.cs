using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using MVCCoreQueryEncrypt.ServiceConfiguration;

namespace MVCCoreQueryEncrypt
{
    /// <summary>
    /// default implementation class for having encrypt decrypt
    /// </summary>
    public class EncryptDecrypt : IEncryptDecrypt
    {
        private static readonly byte[] Salt;
        static EncryptDecrypt()
        {
            var encryptSalt = ServicesExtensions.MvcEncryptSalt;
            
            if (string.IsNullOrWhiteSpace(encryptSalt))
            {
                throw new ArgumentNullException("Salt");
            }

            Salt = Encoding.ASCII.GetBytes(encryptSalt);
        }

        readonly string _sharedSecret;
        /// <summary>
        /// encrypt constructor
        /// </summary>
        /// <param name="sharedSecret"></param>
        public EncryptDecrypt(string sharedSecret)
        {
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("Secret");

            this._sharedSecret = sharedSecret;
        }
        
        /// <summary>
        /// http://stackoverflow.com/questions/202011/encrypt-and-decrypt-a-string
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        string IEncryptDecrypt.DecryptString(string decryptKey)
        {

            if (string.IsNullOrEmpty(decryptKey))
                throw new ArgumentNullException("decryptKey");
            //if it is not base64, return same value - it is not encrypted
            if (!decryptKey.IsBase64String())
                return decryptKey;

            // generate the key from the shared secret and the salt
            var key = new Rfc2898DeriveBytes(_sharedSecret, Salt);

            // Create the streams used for decryption.                
            var bytes = Convert.FromBase64String(decryptKey);
            using var msDecrypt = new MemoryStream(bytes);
            using var aesAlg = new RijndaelManaged();
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
            aesAlg.IV = ReadByteArray(msDecrypt);

            var deCryptoTransform = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            using var csDecrypt = new CryptoStream(msDecrypt, deCryptoTransform, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            return srDecrypt.ReadToEnd();
        }


        private static byte[] ReadByteArray(Stream s)
        {
            var rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            var buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }

        /// <summary>
        /// http://stackoverflow.com/questions/202011/encrypt-and-decrypt-a-string
        /// </summary>
        /// <param name="value"></param>
        /// <returns>base64 crypt</returns>
        string IEncryptDecrypt.EncryptString(string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentNullException("value");


            // generate the key from the shared secret and the salt
            var key = new Rfc2898DeriveBytes(_sharedSecret, Salt);

            // Create a RijndaelManaged object
            using var aesAlg = new RijndaelManaged();
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

            // Create a decryptor to perform the stream transform.
            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using var msEncrypt = new MemoryStream();
            // prepend the IV
            msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
            msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using var swEncrypt = new StreamWriter(csEncrypt);
                swEncrypt.Write(value);
            }
            return Convert.ToBase64String(msEncrypt.ToArray());
        }
    }
}
