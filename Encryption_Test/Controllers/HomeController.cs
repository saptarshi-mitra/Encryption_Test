using Encryption_Test.Models.ViewModels;
using Encryption_Test.Utils;
using Microsoft.Ajax.Utilities;
using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;

namespace Encryption_Test.Controllers
{
    public class HomeController : Controller
    {
        private const string PublicKeyFileName = "public.pem";
        private const string PrivateKeyFileName = "private.pem";
        private readonly CryptoHelper _crypto = new CryptoHelper();
        
        private const int TAG_SIZE_BITS = 128;

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(LoginModel loginModel)
        {
            string encryptedMsg = "", aesKey = "", aesIv = "";
            string rsaKeyPath  = Server.MapPath($"~/App_Data/{PrivateKeyFileName}");
            var aesParts = loginModel.EncryptedMsg.Split('~');
            if (aesParts.Length == 3)
            {
                encryptedMsg = aesParts[0];
                aesKey = aesParts[1];
                aesIv = aesParts[2];
            }

            var aesKeyDecrypted = _crypto.RsaDecrypt(aesKey, rsaKeyPath);
            var aesIvDecrypted = _crypto.RsaDecrypt(aesIv, rsaKeyPath);

            string aesKeyDecryptedStr = BitConverter.ToString(aesKeyDecrypted).Replace("-", ""); ; ;
            string aesIvDecryptedStr = BitConverter.ToString(aesIvDecrypted).Replace("-", "");

            CustomerModel customerModel = GetModel<CustomerModel>(loginModel);
            return View();
        }

        public JsonResult GetPublicKey()
        {
            try
            {
                var pemPath = Server.MapPath($"~/App_Data/{PublicKeyFileName}");
                
                if (!System.IO.File.Exists(pemPath))
                    return Json(new { error = "Public key file not found." }, JsonRequestBehavior.AllowGet);

                var publicKeyPem = System.IO.File.ReadAllText(pemPath);
                var publicKeyBase64 = StripPemHeaders(publicKeyPem);
                return Json(new { publicKey = publicKeyBase64 }, JsonRequestBehavior.AllowGet);
            }
            catch(Exception ex)
            {
                return Json(ex, JsonRequestBehavior.AllowGet);
            }
        }

        

        private string StripPemHeaders(string pem)
        {
            var cleanedPem = pem.Replace("-----BEGIN PUBLIC KEY-----", "")
                                .Replace("-----END PUBLIC KEY-----", "")
                                .Replace("\n", "")
                                .Replace("\r", "");
            return cleanedPem;
        }

        public T GetModel<T>(LoginModel Model)
        {
            string encryptedMsg="", key="", iv="";
            var aesParts = Model.EncryptedMsg.Split('~');
            if (aesParts.Length == 3) {
                encryptedMsg = aesParts[0];
                key = aesParts[1];
                iv = aesParts[2];
            }
            var decryptedStr = "";//_crypto.Decrypt(encryptedMsg, Convert.FromBase64String(key), Convert.FromBase64String(iv));
            return JsonConvert.DeserializeObject<T>(decryptedStr);
        }
    }
}