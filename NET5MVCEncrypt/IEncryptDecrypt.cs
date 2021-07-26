namespace MVCCoreQueryEncrypt
{
    /// <summary>
    /// default interface to encrypt/decrypt data
    /// </summary>
    public interface IEncryptDecrypt
    {
        /// <summary>
        /// encrypt string 
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        internal string EncryptString(string value);
        /// <summary>
        /// decrypt string
        /// Please return the original value if the decryption does not work
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        internal string DecryptString(string value);
    }
}
