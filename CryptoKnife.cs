using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IISResetMe.PshUtils
{
    public class CryptoKnife
    {
        public class RSAKeyPair 
        {
            public readonly string PrivateKey;
            public readonly string PublicKey;

            public RSAKeyPair(string privateKey, string publicKey) 
            {
                this.PrivateKey = privateKey;
                this.PublicKey = publicKey;
            }
        }

        enum ASNTypeTag : int
        {
            // TODO: moar tag numbers!!!

            Reserved    = 0x00,
            Boolean     = 0x01,
            Integer     = 0x02,
            BitString   = 0x03,
            OctetString = 0x04,
            NullString  = 0x05,
            OID         = 0x06,

            UTF8String  = 0x0C,
            OIDRelative = 0x0D,

            Sequence    = 0x30
        }

        private static RSACryptoServiceProvider GenerateRSAPair(int keySize = 2048)
        {
            return new RSACryptoServiceProvider(keySize);
        }

        public static RSAKeyPair NewRSAKey(int keySize)
        {
            return EncodeKeyPair(GenerateRSAPair(keySize));
        }

        private static RSAKeyPair EncodeKeyPair(RSACryptoServiceProvider csp) 
        {
            RSAParameters RSAParams = csp.ExportParameters(false);
            
            StringBuilder privateKeyBuilder = new StringBuilder();
            using (StringWriter privateKeyWriter = new StringWriter(privateKeyBuilder)) 
            {
                ExportPrivateKey(csp, privateKeyWriter);
            }

            StringBuilder publicKeyBuilder = new StringBuilder();
            using (StringWriter publicKeyWriter = new StringWriter(publicKeyBuilder))
            {
                ExportPublicKey(csp, publicKeyWriter);
            }

            return new RSAKeyPair(privateKeyBuilder.ToString(), publicKeyBuilder.ToString());
        }

        //
        // Rework of a great StackOverflow answer by user Iridium (http://stackoverflow.com/users/381588)
        // Q: C# Export Private/Public RSA key from RSACryptoServiceProvider to PEM string
        // http://stackoverflow.com/a/23739932/712649
        //
        private static void ExportPrivateKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {
            if (csp.PublicOnly)
                throw new ArgumentException("CSP does not contain a private key, unable to export private key");

            // TODO: To include pem headers or not... 
            string pemHeader = "-----BEGIN RSA PRIVATE KEY-----";
            string pemFooter = "-----END RSA PRIVATE KEY-----";

            var KeyParams = csp.ExportParameters(true);

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);

                EncodeTag(writer, ASNTypeTag.Sequence);
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);

                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 });
                    EncodeIntegerBigEndian(innerWriter, KeyParams.Modulus);
                    EncodeIntegerBigEndian(innerWriter, KeyParams.Exponent);
                    EncodeIntegerBigEndian(innerWriter, KeyParams.D);
                    EncodeIntegerBigEndian(innerWriter, KeyParams.P);
                    EncodeIntegerBigEndian(innerWriter, KeyParams.Q);
                    EncodeIntegerBigEndian(innerWriter, KeyParams.DP);
                    EncodeIntegerBigEndian(innerWriter, KeyParams.DQ);
                    EncodeIntegerBigEndian(innerWriter, KeyParams.InverseQ);

                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();

                outputStream.WriteLine(pemHeader);

                for (var i = 0; i < base64.Length; i += 64)
                {                    
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }

                outputStream.WriteLine(pemFooter);
            }
        }

        //
        // Rework of a great StackOverflow answer by user Iridium (http://stackoverflow.com/users/381588)
        // Q: C# RSA Public Key Output Not Correct
        // http://stackoverflow.com/a/28407693/712649
        //
        private static void ExportPublicKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {

            string pemHeader = "-----BEGIN PUBLIC KEY-----";
            string pemFooter = "-----END PUBLIC KEY-----";

            var KeyParams = csp.ExportParameters(false);

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                EncodeTag(writer, ASNTypeTag.Sequence);
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeTag(innerWriter, ASNTypeTag.Sequence);
                    EncodeLength(innerWriter, 13);

                    // TODO: abstract away OIDs
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    
                    EncodeTag(innerWriter, ASNTypeTag.OID);
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    EncodeOid(innerWriter, rsaEncryptionOid);
                    EncodeTag(innerWriter, ASNTypeTag.NullString);
                    EncodeLength(innerWriter, 0);

                    EncodeTag(innerWriter, ASNTypeTag.BitString);
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        EncodeTag(bitStringWriter, ASNTypeTag.Reserved);
                        EncodeTag(bitStringWriter, ASNTypeTag.Sequence);

                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, KeyParams.Modulus);
                            EncodeIntegerBigEndian(paramsWriter, KeyParams.Exponent);

                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }

                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }

                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();

                outputStream.WriteLine(pemHeader);
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine(pemFooter);
            }
        }

        private static void EncodeTag(BinaryWriter stream, ASNTypeTag tag)
        {
            stream.Write((byte)tag);
        }

        private static void EncodeOid(BinaryWriter stream, byte[] oid)
        {
            stream.Write(oid);
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", "Length must be non-negative");

            if(length < 0x80) 
            {
                stream.Write((byte)length);
            }
            else 
            {
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0) {
                    temp >>= 8;
                    bytesRequired++;
                }

                stream.Write((byte)(bytesRequired | 0x80));

                for (var i = bytesRequired - 1; i >= 0; i--) {
                    stream.Write((byte)(length >> (8 * i) & 0xFF));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true) 
        {
            stream.Write((byte)0x02);

            var prefixZeros = 0;

            for (var i = 0; i < value.Length; i++) 
            {
                if (value[i] != 0) 
                    break;

                prefixZeros++;
            }

            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0x00);
            }
            else 
            {
                if (forceUnsigned && value[prefixZeros] > 0x7F)
                {
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0x00);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }

                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
    }
}
