using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption_Test.Utils
{
    public class BouncyCastleEncryption
    {
        public static string Encrypt(string plainText, string publicKey)
        {
            try
            {
                var keyReader = new StringReader(publicKey);
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(keyReader);
                var pubKey = (RsaKeyParameters)pemReader.ReadObject();

                var cipher = new RsaEngine();
                cipher.Init(true, pubKey);  // true for encryption mode

                byte[] input = Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = cipher.ProcessBlock(input, 0, input.Length);
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception ex)
            {
                throw new Exception("Error during encryption: " + ex.Message);
            }
        }

        // RSA Decryption
        public static string Decrypt(string cipherText, string privateKey)
        {
            try
            {
                var keyReader = new StringReader(privateKey);
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(keyReader);
                var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

                // Extract the private key
                var privKey = (RsaKeyParameters)keyPair.Private;  // Use the Private key part here

                var cipher = new RsaEngine();
                cipher.Init(false, privKey);  // false for decryption mode

                byte[] input = Convert.FromBase64String(cipherText);
                byte[] decrypted = cipher.ProcessBlock(input, 0, input.Length);
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                throw new Exception("Error during decryption: " + ex.Message);
            }
        }

        public static void GenerateRsaKeyPair()
        {
            // Initialize the key pair generator with 2048 bits key size
            var keyGeneration = new RsaKeyPairGenerator();
            keyGeneration.Init(new KeyGenerationParameters(new SecureRandom(), 2048));

            // Generate the key pair
            AsymmetricCipherKeyPair keyPair = keyGeneration.GenerateKeyPair();

            // Export the public key to a PEM file
            using (var writer = new StreamWriter("D:\\Code\\Encryption\\Encryption_Test\\Encryption_Test\\App_Data\\public.pem"))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(keyPair.Public);
                pemWriter.Writer.Close();  // Explicitly close the writer
            }

            // Export the private key to a PEM file
            using (var writer = new StreamWriter("D:\\Code\\Encryption\\Encryption_Test\\Encryption_Test\\App_Data\\private.pem"))
            {
                var pemWriterPriv = new PemWriter(writer);
                pemWriterPriv.WriteObject(keyPair.Private);
                pemWriterPriv.Writer.Close();  // Explicitly close the writer
            }
        }

    }
}