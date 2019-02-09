//----------------------------------------------------------------------------------
// <copyright file="CryptoBase.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/10/2019</date>
// <summary>Crypto Base class</summary>
//-----------------------------------------------------------------------------------

namespace Prakrishta.Cryptography.Core
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Base class for crypto engine classes
    /// </summary>
    public abstract class CryptoBase
    {
        /// <summary>
        /// Holds block size constant
        /// </summary>
        protected const int BlockSize = 128;

        /// <summary>
        /// Initializes a new instance of <see cref="CryptoBase"/> class.
        /// </summary>
        /// <param name="cipherMode">Cipher mode</param>
        /// <param name="paddingMode">Padding mode</param>
        /// <param name="keySize">Key size</param>
        /// <param name="derivationIterations">Number of iterations</param>
        public CryptoBase(CipherMode cipherMode, PaddingMode paddingMode, int keySize, int derivationIterations)
        {
            KeySizeValidator keySizeValidator = new KeySizeValidator(keySize);

            this.CipherMode = cipherMode;
            this.PaddingMode = paddingMode;
            this.KeySize = keySize;
            this.DerivationIterations = derivationIterations;
        }

        /// <summary>
        /// Gets Cipher Mode
        /// </summary>
        protected CipherMode CipherMode { get;  }

        /// <summary>
        /// Gets Padding Mode
        /// </summary>
        protected PaddingMode PaddingMode { get; }

        /// <summary>
        /// Gets key size
        /// </summary>
        protected int KeySize { get; }

        /// <summary>
        /// Gets Derivation Iterations
        /// </summary>
        protected int DerivationIterations { get; }

        /// <summary>
        /// Gets salt byte length
        /// </summary>
        protected int SaltLength => this.KeySize / 8;

        /// <summary>
        /// Gets initialization vector length
        /// </summary>
        protected int IvLength => BlockSize / 8;

        /// <inheritdoc />
        public IEnumerable<byte> GetSaltBytes(string cipherText)
        {
            return this.GetSaltBytes(Convert.FromBase64String(cipherText));
        }

        /// <inheritdoc />        
        public IEnumerable<byte> GetInitialVectorBytes(string cipherText)
        {
            return this.GetInitialVectorBytes(Convert.FromBase64String(cipherText));
        }        

        #region |Helper Methods|
        /// <summary>
        /// Get salt bytes for given cipher text
        /// </summary>
        /// <param name="cipherText">Cipher text byte array</param>
        /// <returns>Encoded string</returns>
        private protected IEnumerable<byte> GetSaltBytes(byte[] cipherTextBytes)
        {
            var saltStringBytes = cipherTextBytes.Take(this.SaltLength);
            return saltStringBytes;
        }

        /// <summary>
        /// Get IV bytes for given cipher text
        /// </summary>
        /// <param name="cipherText">Cipher text byte array</param>
        /// <returns>Encoded string</returns>
        private protected IEnumerable<byte> GetInitialVectorBytes(byte[] cipherTextBytes)
        {
            var ivStringBytes = cipherTextBytes.Skip(this.SaltLength).Take(this.IvLength);
            return ivStringBytes;
        }
                
        /// <summary>
        /// Method to generate random (keysize / 8) or (blocksize / 8) bit array for using it as salt 
        /// and initialization vector 
        /// </summary>
        /// <returns></returns>
        private protected byte[] GenerateBitsOfRandomEntropy(string byteType)
        {
            int arrayLength = 8;
            if (byteType == CryptoEngineConstants.Salt)
            {
                arrayLength = this.KeySize / 8;
            }
            else
            {
                arrayLength = BlockSize / 8;
            }

            var randomBytes = new byte[arrayLength];
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
        #endregion
    }
}
