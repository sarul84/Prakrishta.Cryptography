//----------------------------------------------------------------------------------
// <copyright file="CryptoEngineConstants.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/9/2019</date>
// <summary>Crypto Engine Constants</summary>
//-----------------------------------------------------------------------------------

namespace Prakrishta.Cryptography.Core
{
    /// <summary>
    /// Static class that has constants
    /// </summary>
    public static class CryptoEngineConstants
    {
        /// <summary>
        /// Holds constant string that denotes salt
        /// </summary>
        public const string Salt = "Salt";

        /// <summary>
        /// Holds constant string that denotes Initialization vector
        /// </summary>
        public const string InitialVector = "IV";

        /// <summary>
        /// Holds constant value that denotes Min key size
        /// </summary>
        public const int MinKeySize = 128;

        /// <summary>
        /// Holds constant value that denotes Max key size
        /// </summary>
        public const int MaxKeySize = 256;

        /// <summary>
        /// Holds constant value that denotes key interval value
        /// </summary>
        public const int KeyInterval = 64;
    }
}
