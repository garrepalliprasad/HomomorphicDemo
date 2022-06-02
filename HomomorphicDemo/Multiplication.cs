using Microsoft.Research.SEAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HomomorphicDemo
{
    partial class Program
    {
        private static void ExampleMultiplication()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(1024);
            SEALContext context = new SEALContext(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);
            ulong x = 37;
            Plaintext xPlain = new Plaintext(Utilities.ULongToString(x));
            Console.WriteLine($"Express x = {x} as a plaintext polynomial 0x{xPlain}.");

            ulong y = 49;
            Plaintext yPlain = new Plaintext(Utilities.ULongToString(y));
            Console.WriteLine($"Express x = {y} as a plaintext polynomial 0x{yPlain}.");

            Ciphertext xEncrypted = new Ciphertext();
            Console.WriteLine("Encrypt xPlain to xEncrypted.");
            encryptor.Encrypt(xPlain, xEncrypted);
            Console.WriteLine("-------->xEncrypted" + xEncrypted);
            Ciphertext yEncrypted = new Ciphertext();
            Console.WriteLine("Encrypt yPlain to yEncrypted.");
            encryptor.Encrypt(yPlain, yEncrypted);
            Console.WriteLine("-------->yEncrypted" + yEncrypted);
            Plaintext xDecrypted = new Plaintext();
            Console.Write("    + decryption of encrypted_x: ");
            decryptor.Decrypt(xEncrypted, xDecrypted);
            Console.WriteLine($"0x{xDecrypted} ...... Correct.");

            Plaintext yDecrypted = new Plaintext();
            Console.Write("    + decryption of encrypted_y: ");
            decryptor.Decrypt(yEncrypted, yDecrypted);
            Console.WriteLine($"0x{yDecrypted} ...... Correct.");

            Console.WriteLine("Compute xEncrypted.yEncrypted");
            Ciphertext encryptedResult = new Ciphertext();
            evaluator.Multiply(xEncrypted, yEncrypted, encryptedResult);

            Plaintext decryptedResult = new Plaintext();
            Console.Write("    + decryption of encryptedResult: ");
            decryptor.Decrypt(encryptedResult, decryptedResult);
            Console.WriteLine($"0x{decryptedResult} ...... Correct.");

            
        }
    }
}
