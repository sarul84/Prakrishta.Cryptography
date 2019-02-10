//----------------------------------------------------------------------------------
// <copyright file="CryptoEngineFactory.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/10/2019</date>
// <summary>Factory method class that creates Crypto Engines</summary>
//-----------------------------------------------------------------------------------

using System;

namespace Prakrishta.Cryptography.Core
{
    /// <summary>
    /// Class that implements ICryptoEngineFactory interface
    /// </summary>
    public class CryptoEngineFactory
    {
        public static ICryptoEngine GetCryptoEngine(CryptoAlgorithm cryptoAlgorithm, params object[] constructorArguments)
        {
            ICryptoEngine cryptoEngine = null;
            switch (cryptoAlgorithm)
            {
                case CryptoAlgorithm.RijndaelManaged:
                    cryptoEngine = (ICryptoEngine)Activator.CreateInstance(typeof(RijndaelCryptoEngine), constructorArguments);
                    break;
                case CryptoAlgorithm.Aes:
                    cryptoEngine = (ICryptoEngine)Activator.CreateInstance(typeof(AesCryptoEngine), constructorArguments);
                    break;
            }
            return cryptoEngine;
        }
    }
}
