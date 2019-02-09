//----------------------------------------------------------------------------------
// <copyright file="KeySizeValidator.cs" company="Prakrishta Technologies">
//     Copyright (c) 2019 Prakrishta Technologies. All rights reserved.
// </copyright>
// <author>Arul Sengottaiyan</author>
// <date>2/9/2019</date>
// <summary>Key Size Validator</summary>
//-----------------------------------------------------------------------------------

namespace Prakrishta.Cryptography.Core
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;

    /// <summary>
    /// Class that validates Encryption key size value
    /// </summary>
    public sealed class KeySizeValidator
    {
        /// <summary>
        /// Holds allowed key size arrary value
        /// </summary>
        private readonly IEnumerable<int> AesKeySizeArray = new Collection<int> { 128, 192, 256 };

        /// <summary>
        /// Initializes a new instance of <see cref="KeySizeValidator"/> class.
        /// </summary>
        /// <param name="keySize"></param>
        public KeySizeValidator(int keySize)
        {
            if(!AesKeySizeArray.Any(x=> x == keySize))
            {
                throw new ArgumentOutOfRangeException(nameof(keySize), $"Key size value should be one of the following value: 128,192,256");
            }
        }
    }
}
