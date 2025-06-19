using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace ErayKriptoloji.Controllers
{
    public class SHA256Controller : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Index(string mode, string? plainText, IFormFile? uploadedFile)
        {
            string hashResult = string.Empty;

            if (mode == "text" && !string.IsNullOrWhiteSpace(plainText))
            {
                using (var sha256 = SHA256.Create())
                {
                    var bytes = Encoding.UTF8.GetBytes(plainText);
                    var hash = sha256.ComputeHash(bytes);
                    hashResult = BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
            else if (mode == "file" && uploadedFile != null)
            {
                using (var sha256 = SHA256.Create())
                using (var stream = uploadedFile.OpenReadStream())
                {
                    var hash = sha256.ComputeHash(stream);
                    hashResult = BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }

            ViewBag.Mode = mode;
            ViewBag.HashResult = hashResult;
            ViewBag.PlainText = plainText;
            return View();
        }
    }
}
