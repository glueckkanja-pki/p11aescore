using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace p11aescore
{
    class Program
    {
        enum Command { Extract, Create };

        static string[] requestHelpParameters = new string[] { "/?", "-?", "-h", "--help" };
        static void Main(string[] args)
        {
            if (0 == args.Length || requestHelpParameters.Contains(args[0]))
            {
                PrintUsage();
                return;
            }

            string libraryPath = args[0];
            Command currentCommand = Enum.Parse<Command>(args[1]);
            string label = args[2];

            switch(currentCommand)
            {
                case Command.Create:
                    CreateAES256Key(libraryPath, label);
                    break;
                case Command.Extract:
                    string extractionPath = args[3];
                    ExtractKey(libraryPath, label, extractionPath);
                    break;
                default:
                    throw new NotImplementedException($"Unknown command {currentCommand}!");
            }

        }

        private static void ExtractKey(string libraryPath, string label, string extractionPath)
        {
            if (File.Exists(extractionPath))
                throw new Exception($"File {extractionPath} already exists. Aborting.");

            using (IPkcs11Library pkcs11Library = Settings.Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, libraryPath, Settings.AppType))
            {
                List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                ISlot slot = slots.Single(slot => slot.GetTokenInfo().Label == "accelerator");   // nCipher stores its module-protected keys in the accelerator slot

                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                {
                    //// Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Prepare attribute template that defines search criteria
                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));

                    // Initialize searching
                    session.FindObjectsInit(objectAttributes);

                    // Get search results
                    List<IObjectHandle> foundObjects = session.FindObjects(2);

                    // Terminate searching
                    session.FindObjectsFinal();

                    if (foundObjects.Count > 1)
                        throw new Exception($"Found {foundObjects.Count} secret keys with label {label}. Aborting.");
                    if (foundObjects.Count == 0)
                        throw new Exception($"No secret key with label {label} could be found. Aborting.");

                    IObjectHandle aesKey = foundObjects.Single();

                    List<IObjectAttribute> listWithSensitivityValue = session.GetAttributeValue(aesKey, new List<CKA>(new CKA[] { CKA.CKA_SENSITIVE }));
                    bool isSensitive = listWithSensitivityValue[0].GetValueAsBool();

                    if (isSensitive)
                        throw new Exception("The secret key is sensitive. It cannot be exported in plaintext. Aborting.");

                    List<IObjectAttribute> listWithTheValue = session.GetAttributeValue(aesKey, new List<CKA>(new CKA[] { CKA.CKA_VALUE }));

                    byte[] baAesKey = listWithTheValue[0].GetValueAsByteArray();

                    if (baAesKey.Length != 32)
                        throw new Exception($"The secret Key has length {baAesKey.Length}, which is unexpected. As an AES-256 key, it should have 32 bytes length. Aborting.");

                    byte[] baKeyIdentifier = new byte[16];
                    Encoding.UTF8.GetBytes(label).CopyTo(baKeyIdentifier, 0);
                    string keyIdentifier = BitConverter.ToString(baKeyIdentifier).Replace("-", string.Empty);
                    string hexKeyPlain = BitConverter.ToString(baAesKey).Replace("-", string.Empty);

                    using (StreamWriter swExtraction = new StreamWriter(extractionPath))
                    {
                        swExtraction.WriteLine($"TDE Master Encryption Key Identifier: {keyIdentifier}");
                        swExtraction.WriteLine($"TDE Master Encryption Key: {hexKeyPlain}");
                    }

                    session.Logout();
                }
            }
        }

        private static void CreateAES256Key(string libraryPath, string label)
        {
            using (IPkcs11Library pkcs11Library = Settings.Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, libraryPath, Settings.AppType))
            {
                List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                ISlot slot = slots.Single(slot => slot.GetTokenInfo().Label == "accelerator");   // nCipher stores its module-protected keys in the accelerator slot

                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    //// Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);    // PIN is ignored for nCipher HSMs where tokens are unlocked differently

                        // Prepare attribute template of new key
                    List < IObjectAttribute > objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE_LEN, 32));

                    // Specify key generation mechanism
                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_AES_KEY_GEN);

                    // Generate key
                    IObjectHandle newAESKey = session.GenerateKey(mechanism, objectAttributes);

                    session.Logout();
                }
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: P11AESCore.exe PKCS11MODULEPATH COMMAND LABEL [ExtractionPath]");
            Console.WriteLine();
            Console.WriteLine("  PKCS11MODULEPATH  - Path to the PKCS #11 DLL used to connect to the HSM/Smart Card");
            Console.WriteLine("  COMMAND           - What should be done on the HSM? Supported commands:");
            Console.WriteLine("    Extract         - Export an existing AES key and save it as OKV plaintext in ExtractionPath");
            Console.WriteLine("    Create          - Create a new AES-256 key");
            Console.WriteLine();
        }

        /// <summary>
        /// Generates AES symmetric key.
        /// </summary>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <returns>Object handle</returns>
        private static IObjectHandle GenerateAESKey(ISession session)
        {
            // Prepare attribute template of new key
            List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "Core AES Key"));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE_LEN, 32));
            // objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA., false));

            // Specify key generation mechanism
            IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_AES_KEY_GEN);

            // Generate key
            return session.GenerateKey(mechanism, objectAttributes);
        }
    }
}
