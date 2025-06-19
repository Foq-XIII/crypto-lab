using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace ErayKriptoloji.Controllers
{
    public class RSAController : Controller
    {
        [HttpGet]
        public IActionResult GenerateKeys()
        {
            return View();
        }

        [HttpPost]
        public IActionResult GenerateKeys(int keySize)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keySize;
                var keyParams = rsa.ExportParameters(true);

                string publicKey = Convert.ToBase64String(keyParams.Modulus!) + "\n" +
                                   Convert.ToBase64String(keyParams.Exponent!);

                string privateKey = Convert.ToBase64String(keyParams.Modulus!) + "\n" +
                                    Convert.ToBase64String(keyParams.Exponent!) + "\n" +
                                    Convert.ToBase64String(keyParams.D!) + "\n" +
                                    Convert.ToBase64String(keyParams.P!) + "\n" +
                                    Convert.ToBase64String(keyParams.Q!) + "\n" +
                                    Convert.ToBase64String(keyParams.DP!) + "\n" +
                                    Convert.ToBase64String(keyParams.DQ!) + "\n" +
                                    Convert.ToBase64String(keyParams.InverseQ!);

                ViewBag.PublicKey = publicKey;
                ViewBag.PrivateKey = privateKey;
                ViewBag.SelectedKeySize = keySize;
            }

            return View();
        }

        [HttpGet]
        public IActionResult Encrypt()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Encrypt(string plaintext, string publicKeyFull)
        {
            try
            {
                var lines = publicKeyFull.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2)
                    throw new Exception("Lütfen geçerli bir Public Key (Modulus + Exponent) giriniz.");

                var modulusBytes = Convert.FromBase64String(lines[0].Trim());
                var exponentBytes = Convert.FromBase64String(lines[1].Trim());

                var rsaParams = new RSAParameters
                {
                    Modulus = modulusBytes,
                    Exponent = exponentBytes
                };

                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(rsaParams);
                    byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plaintext);
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                    ViewBag.EncryptedText = Convert.ToBase64String(encryptedData);
                }
            }
            catch (Exception ex)
            {
                ViewBag.EncryptedText = "HATA: " + ex.Message;
            }

            ViewBag.Plaintext = plaintext;
            ViewBag.PublicKeyFull = publicKeyFull;
            return View();
        }

        [HttpGet]
        public IActionResult Decrypt()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Decrypt(string encryptedText, string privateKeyFull)
        {
            try
            {
                var lines = privateKeyFull.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 8)
                    throw new Exception("Lütfen geçerli ve TAM bir private key (8 satır) giriniz.");

                var rsaParams = new RSAParameters
                {
                    Modulus = Convert.FromBase64String(lines[0].Trim()),
                    Exponent = Convert.FromBase64String(lines[1].Trim()),
                    D = Convert.FromBase64String(lines[2].Trim()),
                    P = Convert.FromBase64String(lines[3].Trim()),
                    Q = Convert.FromBase64String(lines[4].Trim()),
                    DP = Convert.FromBase64String(lines[5].Trim()),
                    DQ = Convert.FromBase64String(lines[6].Trim()),
                    InverseQ = Convert.FromBase64String(lines[7].Trim())
                };

                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(rsaParams);
                    byte[] encryptedBytes = Convert.FromBase64String(encryptedText.Trim());
                    byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
                    ViewBag.DecryptedText = Encoding.UTF8.GetString(decryptedBytes);
                }
            }
            catch (Exception ex)
            {
                ViewBag.DecryptedText = "HATA: " + ex.Message;
            }

            ViewBag.EncryptedText = encryptedText;
            ViewBag.PrivateKeyFull = privateKeyFull;
            return View();
        }
    }
}
