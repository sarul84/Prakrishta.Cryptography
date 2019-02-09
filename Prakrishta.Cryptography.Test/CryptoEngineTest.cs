using Microsoft.VisualStudio.TestTools.UnitTesting;
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
        public void EncryptionDecryptionTest(string plainText)
        {
            //Arrange
            ICryptoEngine cryptoEngine = new CryptoEngine();

            //Act
            var cipherText = cryptoEngine.Encrypt(plainText, encryptionKey);
            var decipher = cryptoEngine.Decrypt(cipherText, encryptionKey);

            //Assert
            Assert.AreEqual(plainText, decipher, "Encryption failed");
        }

        [TestMethod]
        [DataRow("CryptoTesting")]
        [DataRow("Cryptography")]
        [DataRow("ArulSengottaiyan")]
        public void EncryptionTest(string plainText)
        {
            //Arrange
            ICryptoEngine cryptoEngine = new CryptoEngine();
            var cipherText = cryptoEngine.Encrypt(plainText, encryptionKey);

            //Act
            var salt = cryptoEngine.GetSaltBytes(cipherText).ToArray();
            var last4Bytes = cryptoEngine.GetIvBytes(cipherText).ToArray();
            var cipherAgain = cryptoEngine.Encrypt(plainText, encryptionKey, salt, last4Bytes);

            //Assert
            Assert.AreEqual(cipherText, cipherAgain, "Encryption failed");
        }
    }
}
