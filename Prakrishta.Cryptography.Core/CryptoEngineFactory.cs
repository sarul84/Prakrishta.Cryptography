//----------------------------------------------------------------------------------
// <copyright file="CryptoEngineFactory.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/10/2019</date>
// <summary>Factory method class that creates Crypto Engines</summary>
//-----------------------------------------------------------------------------------

namespace Prakrishta.Cryptography.Core
{
    /// <summary>
    /// Class that implements ICryptoEngineFactory interface
    /// </summary>
    public class CryptoEngineFactory : ICryptoEngineFactory
    {
        public ICryptoEngine GetCryptoEngine(CryptoAlgorithm cryptoAlgorithm)
        {
            ICryptoEngine cryptoEngine = null;
            switch(cryptoAlgorithm)
            {
                case CryptoAlgorithm.RijndaelManaged:
                    cryptoEngine = new RijndaelCryptoEngine();
                    break;
                case CryptoAlgorithm.Aes:
                    cryptoEngine = new AesCryptoEngine();
                    break;
            }
            return cryptoEngine;
        }
    }
}
