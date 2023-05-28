using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using MVCCoreQueryEncrypt.ServiceConfiguration;

namespace MVCCoreQueryEncrypt
{
    /// <summary>
    /// default implementation class for having encrypt decrypt
    /// </summary>
    public class EncryptDecrypt : IEncryptDecrypt
    {
        private static readonly byte[] salt;
        static EncryptDecrypt()
        {
            var val = ServicesExtensions.MvcDecryptFilterSecret;
            if (string.IsNullOrWhiteSpace(val))
            {
                val = "http://www.dutappfactory.tech/";
            }
            salt = Encoding.ASCII.GetBytes(val);
        }
        string sharedSecret;
        /// <summary>
        /// encrypt constructor
        /// </summary>
        /// <param name="sharedSecret"></param>
        public EncryptDecrypt(string sharedSecret)
        {
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            this.sharedSecret = sharedSecret;
        }



        /// <summary>
        /// http://stackoverflow.com/questions/202011/encrypt-and-decrypt-a-string
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public string DecryptString(string value)
        {

            if (string.IsNullOrEmpty(value))
                throw new ArgumentNullException("value");

            byte[] bytes = WebEncoders.Base64UrlDecode(value);

            var newUrlDecode = Encoding.ASCII.GetString(bytes);

            if (!string.Equals(newUrlDecode, value, StringComparison.Ordinal) && newUrlDecode.IsBase64String())
                value = newUrlDecode;

            //if it is not base64, return same value - it is not encrypted
            if (!value.IsBase64String())
                throw new ArgumentException("value is not encrypted");
            // Declare the RijndaelManaged object
            // used to decrypt the data.
            Aes aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;


            // generate the key from the shared secret and the salt
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, salt, 3, HashAlgorithmName.SHA256);

            // Create the streams used for decryption.
            var base64Decoder = Convert.FromBase64String(value);
            using (MemoryStream msDecrypt = new MemoryStream(base64Decoder))
            {
                // Create a RijndaelManaged object
                // with the specified key and IV.
                aesAlg = Aes.Create();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                // Get the initialization vector from the encrypted stream
                aesAlg.IV = ReadByteArray(msDecrypt);

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                }
            }

            // Clear the RijndaelManaged object.
            aesAlg?.Clear();


            return plaintext;
        }


        private static byte[] ReadByteArray(Stream s)
        {
            byte[] buffer = null;

            var rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }
            buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
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
        public string EncryptString(string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentNullException("value");

            string outStr = null;                       // Encrypted string to return
            Aes aesAlg = null;              // RijndaelManaged object used to encrypt the data.


            // generate the key from the shared secret and the salt
            var key = new Rfc2898DeriveBytes(sharedSecret, salt, 3, HashAlgorithmName.SHA256);

            // Create a RijndaelManaged object
            aesAlg = Aes.Create();
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

            // Create a decryptor to perform the stream transform.
            var encryption = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (var msEncrypt = new MemoryStream())
            {
                // prepend the IV
                msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                using (var csEncrypt = new CryptoStream(msEncrypt, encryption, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(value);
                    }
                }
                outStr = Convert.ToBase64String(msEncrypt.ToArray());

            }


            aesAlg?.Clear();

            // Return the encrypted bytes from the memory stream.
            var bytes = Encoding.ASCII.GetBytes(outStr ?? "");
            return WebEncoders.Base64UrlEncode(bytes);
        }
    }

}
