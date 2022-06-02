﻿using Microsoft.Research.SEAL;
using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HomomorphicDemo
{
    partial class Program
    {
        /*
        In `1_BFV_Basics.cs' we showed how to perform a very simple computation using the
        BFV scheme. The computation was performed modulo the PlainModulus parameter, and
        utilized only one coefficient from a BFV plaintext polynomial. This approach has
        two notable problems:
            (1) Practical applications typically use integer or real number arithmetic,
                not modular arithmetic;
            (2) We used only one coefficient of the plaintext polynomial. This is really
                wasteful, as the plaintext polynomial is large and will in any case be
                encrypted in its entirety.
        For (1), one may ask why not just increase the PlainModulus parameter until no
        overflow occurs, and the computations behave as in integer arithmetic. The problem
        is that increasing PlainModulus increases noise budget consumption, and decreases
        the initial noise budget too.
        In these examples we will discuss other ways of laying out data into plaintext
        elements (encoding) that allow more computations without data type overflow, and
        can allow the full plaintext polynomial to be utilized.
        */
       

        private static void ExampleBatchEncoder()
        {
            Utilities.PrintExampleBanner("Example: Encoders / Batch Encoder");

            /*
            [BatchEncoder] (For BFV scheme only)
            Let N denote the PolyModulusDegree and T denote the PlainModulus. Batching
            allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, with
            each element an integer modulo T. In the matrix view, encrypted operations act
            element-wise on encrypted matrices, allowing the user to obtain speeds-ups of
            several orders of magnitude in fully vectorizable computations. Thus, in all
            but the simplest computations, batching should be the preferred method to use
            with BFV, and when used properly will result in implementations outperforming
            anything done with the IntegerEncoder.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);

            /*
            To enable batching, we need to set the plain_modulus to be a prime number
            congruent to 1 modulo 2*PolyModulusDegree. Microsoft SEAL provides a helper
            method for finding such a prime. In this example we create a 20-bit prime
            that supports batching.
            */
            parms.PlainModulus = PlainModulus.Batching(polyModulusDegree, 20);

            SEALContext context = new SEALContext(parms);
            Utilities.PrintParameters(context);
            Console.WriteLine();

            /*
            We can verify that batching is indeed enabled by looking at the encryption
            parameter qualifiers created by SEALContext.
            */
            var qualifiers = context.FirstContextData.Qualifiers;
            Console.WriteLine($"Batching enabled: {qualifiers.UsingBatching}");

            KeyGenerator keygen = new KeyGenerator(context);
            keygen.CreatePublicKey(out PublicKey publicKey);
            //PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            keygen.CreateRelinKeys(out RelinKeys relinKeys);
            //RelinKeys relinKeys = keygen.RelinKeysLocal();
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            Batching is done through an instance of the BatchEncoder class.
            */
            BatchEncoder batchEncoder = new BatchEncoder(context);

            /*
            The total number of batching `slots' equals the PolyModulusDegree, N, and
            these slots are organized into 2-by-(N/2) matrices that can be encrypted and
            computed on. Each slot contains an integer modulo PlainModulus.
            */
            ulong slotCount = batchEncoder.SlotCount;
            ulong rowSize = slotCount / 2;
            Console.WriteLine($"Plaintext matrix row size: {rowSize}");

            /*
            The matrix plaintext is simply given to BatchEncoder as a flattened vector
            of numbers. The first `rowSize' many numbers form the first row, and the
            rest form the second row. Here we create the following matrix:
                [ 0,  1,  2,  3,  0,  0, ...,  0 ]
                [ 4,  5,  6,  7,  0,  0, ...,  0 ]
            */
            ulong[] podMatrix = new ulong[slotCount];
            podMatrix[0] = 0;
            podMatrix[1] = 1;
            podMatrix[2] = 2;
            podMatrix[3] = 3;
            podMatrix[rowSize] = 4;
            podMatrix[rowSize + 1] = 5;
            podMatrix[rowSize + 2] = 6;
            podMatrix[rowSize + 3] = 7;

            Console.WriteLine("Input plaintext matrix:");
            Utilities.PrintMatrix(podMatrix, (int)rowSize);

            /*
            First we use BatchEncoder to encode the matrix into a plaintext polynomial.
            */
            Plaintext plainMatrix = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Encode plaintext matrix:");
            batchEncoder.Encode(podMatrix, plainMatrix);

            /*
            We can instantly decode to verify correctness of the encoding. Note that no
            encryption or decryption has yet taken place.
            */
            List<ulong> podResult = new List<ulong>();
            Console.WriteLine("    + Decode plaintext matrix ...... Correct.");
            batchEncoder.Decode(plainMatrix, podResult);
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Next we encrypt the encoded plaintext.
            */
            Ciphertext encryptedMatrix = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Encrypt plainMatrix to encryptedMatrix.");
            encryptor.Encrypt(plainMatrix, encryptedMatrix);
            Console.WriteLine("    + Noise budget in encryptedMatrix: {0} bits",
                decryptor.InvariantNoiseBudget(encryptedMatrix));

            /*
            Operating on the ciphertext results in homomorphic operations being performed
            simultaneously in all 8192 slots (matrix elements). To illustrate this, we
            form another plaintext matrix
                [ 1,  2,  1,  2,  1,  2, ..., 2 ]
                [ 1,  2,  1,  2,  1,  2, ..., 2 ]
            and encode it into a plaintext.
            */
            ulong[] podMatrix2 = new ulong[slotCount];
            for (ulong i = 0; i < slotCount; i++)
            {
                podMatrix2[i] = (i & 1) + 1;
            }
            Plaintext plainMatrix2 = new Plaintext();
            batchEncoder.Encode(podMatrix2, plainMatrix2);
            Console.WriteLine();
            Console.WriteLine("Second input plaintext matrix:");
            Utilities.PrintMatrix(podMatrix2, (int)rowSize);

            /*
            We now add the second (plaintext) matrix to the encrypted matrix, and square
            the sum.
            */
            Utilities.PrintLine();
            Console.WriteLine("Sum, square, and relinearize.");
            evaluator.AddPlainInplace(encryptedMatrix, plainMatrix2);
            evaluator.SquareInplace(encryptedMatrix);
            evaluator.RelinearizeInplace(encryptedMatrix, relinKeys);

            /*
            How much noise budget do we have left?
            */
            Console.WriteLine("    + Noise budget in result: {0} bits",
                decryptor.InvariantNoiseBudget(encryptedMatrix));

            /*
            We decrypt and decompose the plaintext to recover the result as a matrix.
            */
            Plaintext plainResult = new Plaintext();
            Utilities.PrintLine();
            Console.WriteLine("Decrypt and decode result.");
            decryptor.Decrypt(encryptedMatrix, plainResult);
            batchEncoder.Decode(plainResult, podResult);
            Console.WriteLine("    + Result plaintext matrix ...... Correct.");
            Utilities.PrintMatrix(podResult, (int)rowSize);

            /*
            Batching allows us to efficiently use the full plaintext polynomial when the
            desired encrypted computation is highly parallelizable. However, it has not
            solved the other problem mentioned in the beginning of this file: each slot
            holds only an integer modulo plain_modulus, and unless plain_modulus is very
            large, we can quickly encounter data type overflow and get unexpected results
            when integer computations are desired. Note that overflow cannot be detected
            in encrypted form. The CKKS scheme (and the CKKSEncoder) addresses the data
            type overflow issue, but at the cost of yielding only approximate results.
            */
        }

        static private void ExampleCKKSEncoder()
        {
            Utilities.PrintExampleBanner("Example: Encoders / CKKS Encoder");

            /*
            [CKKSEncoder] (For CKKS scheme only)
            In this example we demonstrate the Cheon-Kim-Kim-Song (CKKS) scheme for
            computing on encrypted real or complex numbers. We start by creating
            encryption parameters for the CKKS scheme. There are two important
            differences compared to the BFV scheme:
                (1) CKKS does not use the PlainModulus encryption parameter;
                (2) Selecting the CoeffModulus in a specific way can be very important
                    when  the CKKS scheme. We will explain this further in the file
                    `CKKS_Basics.cs'. In this example we use CoeffModulus.Create to
                    generate 5 40-bit prime numbers.
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);

            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.Create(
                polyModulusDegree, new int[] { 40, 40, 40, 40, 40 });

            /*
            We create the SEALContext as usual and print the parameters.
            */
            SEALContext context = new SEALContext(parms);
            Utilities.PrintParameters(context);
            Console.WriteLine();

            /*
            Keys are created the same way as for the BFV scheme.
            */
            KeyGenerator keygen = new KeyGenerator(context);
            keygen.CreatePublicKey(out PublicKey publicKey);
            SecretKey secretKey = keygen.SecretKey;
            keygen.CreateRelinKeys(out RelinKeys relinKeys);

            /*
            We also set up an Encryptor, Evaluator, and Decryptor as usual.
            */
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            To create CKKS plaintexts we need a special encoder: there is no other way
            to create them. The IntegerEncoder and BatchEncoder cannot be used with the
            CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
            Plaintext objects, which can subsequently be encrypted. At a high level this
            looks a lot like what BatchEncoder does for the BFV scheme, but the theory
            behind it is completely different.
            */
            CKKSEncoder encoder = new CKKSEncoder(context);

            /*
            In CKKS the number of slots is PolyModulusDegree / 2 and each slot encodes
            one real or complex number. This should be contrasted with BatchEncoder in
            the BFV scheme, where the number of slots is equal to PolyModulusDegree
            and they are arranged into a matrix with two rows.
            */
            ulong slotCount = encoder.SlotCount;
            Console.WriteLine($"Number of slots: {slotCount}");

            /*
            We create a small vector to encode; the CKKSEncoder will implicitly pad it
            with zeros to full size (PolyModulusDegree / 2) when encoding.
            */
            double[] input = new double[] { 0.0, 1.1, 2.2, 3.3 };
            Console.WriteLine("Input vector: ");
            Utilities.PrintVector(input);

            /*
            Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
            will be scaled up by the parameter `scale'. This is necessary since even in
            the CKKS scheme the plaintext elements are fundamentally polynomials with
            integer coefficients. It is instructive to think of the scale as determining
            the bit-precision of the encoding; naturally it will affect the precision of
            the result.
            In CKKS the message is stored modulo CoeffModulus (in BFV it is stored modulo
            PlainModulus), so the scaled message must not get too close to the total size
            of CoeffModulus. In this case our CoeffModulus is quite large (200 bits) so
            we have little to worry about in this regard. For this simple example a 30-bit
            scale is more than enough.
            */
            Plaintext plain = new Plaintext();
            double scale = Math.Pow(2.0, 30);
            Utilities.PrintLine();
            Console.WriteLine("Encode input vector.");
            encoder.Encode(input, scale, plain);

            /*
            We can instantly decode to check the correctness of encoding.
            */
            List<double> output = new List<double>();
            Console.WriteLine("    + Decode input vector ...... Correct.");
            encoder.Decode(plain, output);
            Utilities.PrintVector(output);

            /*
            The vector is encrypted the same was as in BFV.
            */
            Ciphertext encrypted = new Ciphertext();
            Utilities.PrintLine();
            Console.WriteLine("Encrypt input vector, square, and relinearize.");
            encryptor.Encrypt(plain, encrypted);

            /*
            Basic operations on the ciphertexts are still easy to do. Here we square
            the ciphertext, decrypt, decode, and print the result. We note also that
            decoding returns a vector of full size (PolyModulusDegree / 2); this is
            because of the implicit zero-padding mentioned above.
            */
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);

            /*
            We notice that the scale in the result has increased. In fact, it is now
            the square of the original scale: 2^60.
            */
            Console.WriteLine("    + Scale in squared input: {0} ({1} bits)",
                encrypted.Scale,
                (int)Math.Ceiling(Math.Log(encrypted.Scale, newBase: 2)));
            Utilities.PrintLine();
            Console.WriteLine("Decrypt and decode.");
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, output);
            Console.WriteLine("    + Result vector ...... Correct.");
            Utilities.PrintVector(output);

            /*
            The CKKS scheme allows the scale to be reduced between encrypted computations.
            This is a fundamental and critical feature that makes CKKS very powerful and
            flexible. We will discuss it in great detail in `3_Levels.cs' and later in
            `4_CKKS_Basics.cs'.
            */
        }

        private static void ExampleEncoders()
        {
            Utilities.PrintExampleBanner("Example: Encoders");

            /*
            Run all encoder examples.
            */
            
            ExampleBatchEncoder();
            ExampleCKKSEncoder();
        }
    }
}
