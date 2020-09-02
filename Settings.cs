/*
 *  Copyright 2012-2020 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using System;
using System.IO;
using System.Reflection;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Logging;
using LLA40 = Net.Pkcs11Interop.LowLevelAPI40;
using LLA41 = Net.Pkcs11Interop.LowLevelAPI41;
using LLA80 = Net.Pkcs11Interop.LowLevelAPI80;
using LLA81 = Net.Pkcs11Interop.LowLevelAPI81;

// Note: Code in this file is maintained manually.

namespace Net.Pkcs11Interop.Tests
{
    /// <summary>
    /// Test settings.
    /// </summary>
    public static class Settings
    {
        #region Properties that almost always need to be configured before the tests are executed

        /// <summary>
        /// Factories to be used by Developer and Pkcs11Interop library
        /// </summary>
        public static Pkcs11InteropFactories Factories = new Pkcs11InteropFactories();

        /// <summary>
        /// Type of application that will be using PKCS#11 library.
        /// When set to AppType.MultiThreaded unmanaged PKCS#11 library performs locking to ensure thread safety.
        /// </summary>
        public static AppType AppType = AppType.MultiThreaded;

        /// <summary>
        /// Serial number of token (smartcard) that should be used by these tests.
        /// First slot with token present is used when both TokenSerial and TokenLabel properties are null.
        /// </summary>
        public static string TokenSerial = null;

        /// <summary>
        /// Label of the token (smartcard) that should be used by these tests.
        /// First slot with token present is used when both TokenSerial and TokenLabel properties are null.
        /// </summary>
        public static string TokenLabel = null;

        /// <summary>
        /// Application name that is used as a label for all objects created by these tests.
        /// </summary>
        public static string ApplicationName = @"P11AESCore";

        public static string NormalUserPin = "password";

        #endregion

        #region Properties that are set automatically in class constructor

        /// <summary>
        /// Application name that is used as a label for all objects created by these tests.
        /// </summary>
        public static byte[] ApplicationNameArray = null;

        #endregion

        /// <summary>
        /// Static class constructor
        /// </summary>
        static Settings()
        {
            // Uncomment following three lines to enable managed logging via System.Diagnostics.Trace class
            // SimplePkcs11InteropLoggerFactory simpleLoggerFactory = new SimplePkcs11InteropLoggerFactory();
            // simpleLoggerFactory.EnableDiagnosticsTraceOutput();
            // Pkcs11InteropLoggerFactory.SetLoggerFactory(simpleLoggerFactory);

            // Uncomment following three lines to enable unmanaged logging via PKCS11-LOGGER library
            // System.Environment.SetEnvironmentVariable("PKCS11_LOGGER_LIBRARY_PATH", Pkcs11LibraryPath);
            // System.Environment.SetEnvironmentVariable("PKCS11_LOGGER_LOG_FILE_PATH", @"c:\pkcs11-logger.txt");
            // Pkcs11LibraryPath = @"c:\pkcs11-logger-x86.dll";

            // Convert strings to byte arrays
            ApplicationNameArray = ConvertUtils.Utf8StringToBytes(ApplicationName);
        }
    }
}