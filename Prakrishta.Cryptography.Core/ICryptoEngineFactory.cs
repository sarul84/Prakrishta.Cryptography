//----------------------------------------------------------------------------------
// <copyright file="ICryptoEngineFactory.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/10/2019</date>
// <summary>Contract that defines method to get different Crypto Engines</summary>
//-----------------------------------------------------------------------------------

namespace Prakrishta.Cryptography.Core
{
    /// <summary>
    /// Interface that has methods to get different crypto engines
    /// </summary>
    public interface ICryptoEngineFactory
    {
        ICryptoEngine GetCryptoEngine(CryptoAlgorithm cryptoAlgorithm);
    }
}
