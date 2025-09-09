using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;

namespace Encryption_Test.Utils
{
    public class CryptoHelper
    {

        private const int IV_SIZE_BYTES = 12;
        private const int TAG_SIZE_BITS = 128;
        /// <summary>
        /// Reads an RSA private key from a PEM-formatted file and returns it as an XML string.
        /// </summary>
        /// <param name="filePath">The path to the PEM private key file.</param>
        /// <returns>An XML string representation of the private key.</returns>
        public string GetPrivateKeyFromPem(string filePath)
        {
            using (TextReader textReader = new StreamReader(filePath))
            {
                PemReader pemReader = new PemReader(textReader);
                object keyObject = pemReader.ReadObject();

                // The object returned by PemReader.ReadObject() can be an AsymmetricCipherKeyPair,
                // or an RsaPrivateCrtKeyParameters depending on the PEM format (PKCS#8 vs PKCS#1).
                // This logic handles both cases.
                Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters;
                if (keyObject is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair)
                {
                    rsaPrivateCrtKeyParameters = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyPair.Private;
                }
                else
                {
                    rsaPrivateCrtKeyParameters = (Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters)keyObject;
                }

                // Convert the Bouncy Castle parameters to .NET's RSAParameters
                RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(rsaPrivateCrtKeyParameters);

                // Create a new RSACryptoServiceProvider to import the parameters
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(rsaParameters);
                    // Export the key as an XML string, including the private key
                    return rsa.ToXmlString(true);
                }
            }
        }

        public byte[] RsaDecrypt(string EncryptedData, string RsaKeyPath)
        {
            byte[] encKeyBlob = Convert.FromBase64String(EncryptedData);
            AsymmetricKeyParameter rsaPriv = ReadPrivateKeyFromPem(RsaKeyPath);
            return RsaOaepSha256Decrypt(encKeyBlob, rsaPriv);
        }

        private static AsymmetricKeyParameter ReadPrivateKeyFromPem(string pemPath)
        {
            using (var sr = File.OpenText(pemPath))
            {
                var pr = new PemReader(sr);
                object obj = pr.ReadObject();

                if (obj is AsymmetricCipherKeyPair pair)
                    return pair.Private;

                if (obj is AsymmetricKeyParameter keyParam && keyParam.IsPrivate)
                    return keyParam;

                throw new InvalidOperationException("Unsupported or invalid private key PEM.");
            }
        }

        public byte[] RsaOaepSha256Decrypt(byte[] encrypted, AsymmetricKeyParameter privateKey)
        {
            // OAEP parameters: hash=SHA-256 for both hash and mgf1Hash (WebCrypto default for "RSA-OAEP" with SHA-256)
            var rsaEngine = new OaepEncoding(
                new RsaEngine(),
                new Sha256Digest(),  // hash
                new Sha256Digest(),  // mgf1Hash
                null                 // PSource PSource.PSpecified with empty label (WebCrypto uses empty label)
            );

            rsaEngine.Init(false, privateKey); // false = decrypt
            return rsaEngine.ProcessBlock(encrypted, 0, encrypted.Length);
        }

        //public string AesDecrypt(string base64String, byte[] key, byte[] iv)
        //{
        //    byte[] fullCipher = Convert.FromBase64String(base64String);

        //    if (fullCipher.Length < IV_SIZE_BYTES + (TAG_SIZE_BITS / 8))
        //    {
        //        throw new ArgumentException("Ciphertext is too short to contain an IV.", nameof(base64String));
        //    }

        //    // Separate the IV and the actual ciphertext
        //    Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);

        //    int tagSize = TAG_SIZE_BITS / 8;
        //    byte[] cipherText = new byte[fullCipher.Length - iv.Length - tagSize];
        //    Buffer.BlockCopy(fullCipher, iv.Length, cipherText, 0, cipherText.Length);

        //    using (var aesGcm = new AesGcm(key))
        //    {
        //        // The tag is part of the ciphertext in AES-GCM
        //        byte[] cipherText = new byte[cipherTextAndTag.Length - aesGcm.TagSize];
        //        byte[] tag = new byte[aesGcm.TagSize];

        //        Buffer.BlockCopy(cipherTextAndTag, 0, cipherText, 0, cipherText.Length);
        //        Buffer.BlockCopy(cipherTextAndTag, cipherText.Length, tag, 0, tag.Length);

        //        byte[] decryptedBytes = new byte[cipherText.Length];

        //        aesGcm.Decrypt(iv, cipherText, tag, decryptedBytes);
        //        return Encoding.UTF8.GetString(decryptedBytes);
        //    }
        //}
    }
}