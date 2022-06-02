using Microsoft.Research.SEAL;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace HomomorphicDemo
{
    public partial class BmrencodedData
    {
        public int Id { get; set; }
        public string Height { get; set; }
        public string Weight { get; set; }
        public string Age { get; set; }
        public string BMRResult { get; set; }
    }
    partial class Program
    {
        public static string CiphertextToBase64String(Ciphertext ciphertext)
        {
            using (var ms = new MemoryStream())
            {
                ciphertext.Save(ms);
                return Convert.ToBase64String(ms.ToArray());
            }
        }
        public static Ciphertext BuildCiphertextFromBase64String(string base64, SEALContext context)
        {
            var payload = Convert.FromBase64String(base64);

            using (var ms = new MemoryStream(payload))
            {
                var ciphertext = new Ciphertext();
                ciphertext.Load(context, ms);

                return ciphertext;
            }
        }
        private async static void ExampleMultiplyDoubles()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.Create(polyModulusDegree, new int[] { 60, 40, 40, 60 });
            double scale = Math.Pow(2.0, 40);
            SEALContext context = new SEALContext(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);
            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);
            CKKSEncoder encoder = new CKKSEncoder(context);
            
            double w = 13.397, h = 4.799, a = 5.677, c = 88.362,d=1, weight, height, age;
            Console.WriteLine("Enter Weight");
            weight=double.Parse(Console.ReadLine());
            Console.WriteLine("Enter Height");
            height = double.Parse(Console.ReadLine());
            Console.WriteLine("Enter Age");
            age = double.Parse(Console.ReadLine());
            Plaintext wPlain = new Plaintext();
            Plaintext hPlain = new Plaintext();
            Plaintext aPlain = new Plaintext();
            Plaintext cPlain = new Plaintext();
            Plaintext dPlain = new Plaintext();
            Plaintext weightPlain = new Plaintext();
            Plaintext heightPlain = new Plaintext();
            Plaintext agePlain = new Plaintext();

            encoder.Encode(w, scale, wPlain);
            encoder.Encode(h, scale, hPlain);
            encoder.Encode(a, scale, aPlain);
            encoder.Encode(c, scale, cPlain);
            encoder.Encode(d, scale, dPlain);
            encoder.Encode(weight, scale, weightPlain);
            encoder.Encode(height, scale, heightPlain);
            encoder.Encode(age, scale, agePlain);

            Ciphertext wCiphertext=new Ciphertext();
            Ciphertext hCiphertext = new Ciphertext();
            Ciphertext aCiphertext = new Ciphertext();
            Ciphertext cCiphertext = new Ciphertext();
            Ciphertext dCiphertext = new Ciphertext();
            Ciphertext weightCiphertext = new Ciphertext();
            Ciphertext heightCiphertext = new Ciphertext();
            Ciphertext ageCiphertext = new Ciphertext();

            encryptor.Encrypt(wPlain, wCiphertext);
            encryptor.Encrypt(hPlain, hCiphertext);
            encryptor.Encrypt(aPlain, aCiphertext);
            encryptor.Encrypt(cPlain, cCiphertext);
            encryptor.Encrypt(dPlain, dCiphertext);
            encryptor.Encrypt(weightPlain, weightCiphertext);
            encryptor.Encrypt(heightPlain, heightCiphertext);
            encryptor.Encrypt(agePlain, ageCiphertext);

            BmrencodedData bmrencodedData = new BmrencodedData()
            {
                Weight = CiphertextToBase64String(weightCiphertext),
                Height=CiphertextToBase64String(heightCiphertext),
                Age=CiphertextToBase64String(ageCiphertext)
            };
            StringContent content = new StringContent(JsonConvert.SerializeObject(bmrencodedData), Encoding.UTF8, "application/json");
            BmrencodedData data=JsonConvert.DeserializeObject<BmrencodedData>(await content.ReadAsStringAsync());
            //BMR = 13.397W + 4.799H - 5.677A + 88.362
            //BMR = 9.247W + 3.098H - 4.330A + 447.593
            Ciphertext dataWeight=BuildCiphertextFromBase64String(data.Weight,context);
            Ciphertext dataHeight= BuildCiphertextFromBase64String(data.Height, context);
            Ciphertext dataAge= BuildCiphertextFromBase64String(data.Age, context);
            Ciphertext bmrResult=new Ciphertext();
            Ciphertext wtempResult=new Ciphertext();
            Ciphertext htempResult = new Ciphertext();
            Ciphertext atempResult = new Ciphertext();
            Ciphertext cdtempResult=new Ciphertext();
            evaluator.Multiply(wCiphertext,dataWeight,wtempResult);
            evaluator.Multiply(hCiphertext,dataHeight,htempResult);
            evaluator.Multiply(aCiphertext,dataAge,atempResult);
            evaluator.Multiply(cCiphertext, dCiphertext, cdtempResult);
            evaluator.Add(wtempResult,htempResult,bmrResult);
            evaluator.Sub(bmrResult, atempResult, bmrResult);
            evaluator.Add(bmrResult, cdtempResult, bmrResult);
            bmrencodedData.BMRResult=CiphertextToBase64String(bmrResult);

            Plaintext bmrPlain=new Plaintext();
            List<double> bmr = new List<double>();

            decryptor.Decrypt(bmrResult,bmrPlain);
            encoder.Decode(bmrPlain, bmr);
            Console.WriteLine("Done"+bmr[0]);










        }
    }
}
