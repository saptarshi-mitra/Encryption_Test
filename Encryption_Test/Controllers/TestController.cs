using Encryption_Test.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Encryption_Test.Controllers
{
    public class TestController : Controller
    {

        private string _publicKey = System.IO.File.ReadAllText(@"D:\Code\Encryption\Encryption_Test\Encryption_Test\App_Data\public.pem");
        private string _privateKey = System.IO.File.ReadAllText(@"D:\Code\Encryption\Encryption_Test\Encryption_Test\App_Data\private.pem");

        // GET: Encryption
        public ActionResult Index()
        {
            return View();
        }

        // POST: Encrypt the message
        [HttpPost]
        public ActionResult EncryptMessage(string message)
        {
            string encryptedMessage = BouncyCastleEncryption.Encrypt(message, _publicKey);
            ViewBag.EncryptedMessage = encryptedMessage;
            return View("Index");
        }

        // POST: Decrypt the message
        [HttpPost]
        public ActionResult DecryptMessage(string encryptedMessage)
        {
            string decryptedMessage = BouncyCastleEncryption.Decrypt(encryptedMessage, _privateKey);
            ViewBag.DecryptedMessage = decryptedMessage;
            return View("Index");
        }

        [HttpGet]
        public ActionResult GenerateRsaKeyPair() {
            BouncyCastleEncryption.GenerateRsaKeyPair();
            return null;
        }
    }
}