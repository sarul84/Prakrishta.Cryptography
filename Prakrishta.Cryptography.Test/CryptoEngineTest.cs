using Microsoft.VisualStudio.TestTools.UnitTesting;
using Prakrishta.Cryptography.Core;
using System;
using System.Linq;

namespace Prakrishta.Cryptography.Test
{
    [TestClass]
    public class CryptoEngineTest
    {
        private readonly string encryptionKey = "2stu017@aRuLseng$12ind";
        
        [TestMethod]
        [DataRow("CryptoTesting")]
        [DataRow("Cryptography")]
        [DataRow("ArulSengottaiyan")]
        public void Rijndael_EncryptionDecryptionTest(string plainText)
        {
            //Arrange
            ICryptoEngine cryptoEngine = new RijndaelCryptoEngine();

            //Act
            var cipherText = cryptoEngine.Encrypt(plainText, encryptionKey);
            var decipher = cryptoEngine.Decrypt(cipherText, encryptionKey);

            //Assert
            Assert.AreEqual(plainText, decipher, "Encryption / Decryption failed");
        }

        [TestMethod]
        [DataRow("CryptoTesting")]
        [DataRow("Cryptography")]
        [DataRow("ArulSengottaiyan")]
        public void Rijndael_EncryptionTest(string plainText)
        {
            //Arrange
            ICryptoEngine cryptoEngine = new RijndaelCryptoEngine();
            var cipherText = cryptoEngine.Encrypt(plainText, encryptionKey);

            //Act
            var salt = cryptoEngine.GetSaltBytes(cipherText).ToArray();
            var initialVectorBytes = cryptoEngine.GetInitialVectorBytes(cipherText).ToArray();
            var cipherAgain = cryptoEngine.Encrypt(plainText, encryptionKey, salt, initialVectorBytes);

            //Assert
            Assert.AreEqual(cipherText, cipherAgain, "Encryption failed");
        }

        [TestMethod]
        [DataRow(128, "CryptoTesting")]
        [DataRow(192, "Cryptography")]
        [DataRow(256, "ArulSengottaiyan")]
        public void Aes_EncryptionTest(int keySize, string plainText)
        {
            //Arrange
            ICryptoEngine cryptoEngine = new AesCryptoEngine(keySize);
            var cipherText = cryptoEngine.Encrypt(plainText, encryptionKey);

            //Act
            var salt = cryptoEngine.GetSaltBytes(cipherText).ToArray();
            var initialVectorBytes = cryptoEngine.GetInitialVectorBytes(cipherText).ToArray();
            var cipherAgain = cryptoEngine.Encrypt(plainText, encryptionKey, salt, initialVectorBytes);

            //Assert
            Assert.AreEqual(cipherText, cipherAgain, "Encryption failed");
        }

        [TestMethod]
        [DataRow(128, "CryptoTesting")]
        [DataRow(192,"Cryptography")]
        [DataRow(256, "ArulSengottaiyan")]
        [DataRow(192, "Prakrishta")]
        public void Aes_EncryptionDecryptionTest(int size, string plainText)
        {
            //Arrange
            ICryptoEngine cryptoEngine = new AesCryptoEngine(size);

            //Act
            var cipherText = cryptoEngine.Encrypt(plainText, encryptionKey);
            var decipher = cryptoEngine.Decrypt(cipherText, encryptionKey);

            //Assert
            Assert.AreEqual(plainText, decipher, "Encryption / Decryption failed");
        }

        [TestMethod]
        [DataRow(160, "CryptoTesting")]
        [DataRow(1, "Cryptography")]
        [DataRow(-128, "Prakrishta")]
        [DataRow(224, "ArulSengottaiyan")]
        public void Aes_KeySizeExceptionTest(int keySize, string plainText)
        {
            //Arrange
            ICryptoEngine cryptoEngine = new AesCryptoEngine(keySize);

            //Act => Assert
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => cryptoEngine.Encrypt(plainText, encryptionKey));
        }

        [TestMethod]
        [DataRow("CryptoTesting")]
        public void Aes_Rijndael_EncryptionDecryptionTest(string plaintText)
        {
            //Arrange
            ICryptoEngine cryptoEngine1 = new AesCryptoEngine();
            ICryptoEngine cryptoEngine2 = new RijndaelCryptoEngine();

            //Act
            var cipherText = cryptoEngine1.Encrypt(plaintText, encryptionKey);
            var decipherText = cryptoEngine2.Decrypt(cipherText, encryptionKey);

            //Assert
            Assert.AreEqual(plaintText, decipherText, "Both algorithms work differe");
        }

        [TestMethod]
        [DataRow(CryptoAlgorithm.RijndaelManaged, 128)]
        [DataRow(CryptoAlgorithm.Aes, 192)]
        public void SimpleFactory_Test(CryptoAlgorithm algorithm, int keySize)
        {
            //Arrange => Act
            var cryptoEngine = CryptoEngineFactory.GetCryptoEngine(algorithm, keySize);

            //Assert
            Assert.IsNotNull(cryptoEngine, "Factory method didn't work");
        }
    }
}
