//----------------------------------------------------------------------------------
// <copyright file="RijndaelCryptoEngine.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/9/2019</date>
// <summary>Class that does encryption and decryption using Rijndael Algorithm</summary>
//-----------------------------------------------------------------------------------

namespace Prakrishta.Cryptography.Core
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    ///  Crypto engine that uses Rijndael Algorithm
    /// </summary>
    public class RijndaelCryptoEngine : CryptoBase, ICryptoEngine
    {
        #region |Constructor|

        /// <summary>
        /// Initializes a new instance of <see cref="RijndaelCryptoEngine"/> class.
        /// </summary>
        public RijndaelCryptoEngine()
            : this(CryptoEngineConstants.MinKeySize)
        {

        }

        /// <summary>
        /// Initializes a new instance of <see cref="RijndaelCryptoEngine"/> class.
        /// </summary>
        /// <param name="keySize">Key Size</param>
        public RijndaelCryptoEngine(int keySize)
            : this(CipherMode.CBC, PaddingMode.PKCS7, keySize)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RijndaelCryptoEngine"/> class. 
        /// </summary>
        /// <param name="cipherMode">Cipher mode</param>
        /// <param name="paddingMode">Padding mode</param>
        /// <param name="keySize">Key Size</param>
        public RijndaelCryptoEngine(CipherMode cipherMode, PaddingMode paddingMode, int keySize)
            : this(cipherMode, paddingMode, keySize, CryptoEngineConstants.DerivationIterations)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RijndaelCryptoEngine"/> class.
        /// </summary>
        /// <param name="cipherMode">Cipher mode</param>
        /// <param name="paddingMode">Padding mode</param>
        /// <param name="keySize">Key Size</param>
        /// <param name="derivationIterations">Number of iterations</param>
        public RijndaelCryptoEngine(CipherMode cipherMode, PaddingMode paddingMode, int keySize, int derivationIterations)
            : base(cipherMode, paddingMode, keySize, derivationIterations)
        {
        }
        #endregion

        #region |Interface implementation|
        /// <inheritdoc />
        public string Decrypt(string cipherText, string encryptionKey)
        {
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);

            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(this.SaltLength).ToArray();

            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(this.SaltLength)
                .Take(this.IvLength).ToArray();

            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip(this.SaltLength + this.IvLength)
                .Take(cipherTextBytesWithSaltAndIv.Length - (this.SaltLength + this.IvLength)).ToArray();

            using (var password = new Rfc2898DeriveBytes(encryptionKey, saltStringBytes, this.DerivationIterations))
            {
                var keyBytes = password.GetBytes(this.SaltLength);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = CryptoEngineConstants.BlockSize;
                    symmetricKey.Mode = this.CipherMode;
                    symmetricKey.Padding = this.PaddingMode;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        /// <inheritdoc />
        public string Encrypt(string encryptString, string encryptionKey)
        {
            var saltStringBytes = this.GenerateBitsOfRandomEntropy(CryptoEngineConstants.Salt);
            var ivStringBytes = this.GenerateBitsOfRandomEntropy(CryptoEngineConstants.InitialVector);
            return this.Encrypt(encryptString, encryptionKey, saltStringBytes, ivStringBytes);
        }        

        /// <inheritdoc />
        public string Encrypt(string encryptString, string encryptionKey, byte[] saltBytes, byte[] ivBytes)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(encryptString);
            using (var password = new Rfc2898DeriveBytes(encryptionKey, saltBytes, this.DerivationIterations))
            {
                var keyBytes = password.GetBytes(this.SaltLength);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = CryptoEngineConstants.BlockSize;
                    symmetricKey.Mode = this.CipherMode;
                    symmetricKey.Padding = this.PaddingMode;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                var cipherTextBytes = saltBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }
        
        #endregion
    }
}
