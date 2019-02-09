//----------------------------------------------------------------------------------
// <copyright file="ICryptoEngine.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/9/2019</date>
// <summary>Contract that defines encryption and decryption</summary>
//-----------------------------------------------------------------------------------

namespace Prakrishta.Cryptography.Core
{
    using System.Collections.Generic;

    /// <summary>
    /// Interface that has methods for encryption and decryption
    /// </summary>
    public interface ICryptoEngine
    {
        /// <summary>
        /// Method to encrypt cipher text using Rijndeal algorithm
        /// </summary>
        /// <param name="encryptString">String to be encrypted</param>
        /// <param name="encryptionKey">Encryption key</param>
        /// <returns>Encrypted string</returns>
        string Encrypt(string encryptString, string encryptionKey);

        /// <summary>
        /// Method to decrypt cipher text using Rijndeal algorithm
        /// </summary>
        /// <param name="cipherText">Encrypted string</param>
        /// <param name="encryptionKey">Encryption key used for ciphering</param>
        /// <returns></returns>
        string Decrypt(string cipherText, string encryptionKey);

        /// <summary>
        /// Encrypt string with provided salt and iv bytes
        /// </summary>
        /// <param name="encryptString">String to be encrypted</param>
        /// <param name="encryptionKey">Encryption key</param>
        /// <param name="saltBytes">Salt bytes</param>
        /// <param name="ivBytes">Encoded byte array</param>
        /// <returns>Encrypted string</returns>
        string Encrypt(string encryptString, string encryptionKey, byte[] saltBytes, byte[] ivBytes);

        /// <summary>
        /// Get salt bytes for given cipher text
        /// </summary>
        /// <param name="cipherText">Encrypted string</param>
        /// <returns>Encoded string</returns>
        IEnumerable<byte> GetSaltBytes(string cipherText);

        /// <summary>
        /// Get IV bytes for given cipher text
        /// </summary>
        /// <param name="cipherText">Cipher text</param>
        /// <returns>Encoded string</returns>
        IEnumerable<byte> GetInitialVectorBytes(string cipherText);
    }
}
