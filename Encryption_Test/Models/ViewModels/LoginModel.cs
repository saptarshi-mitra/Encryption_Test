using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Encryption_Test.Models.ViewModels
{
    public class LoginModel
    {
        public string EncryptedMsg { get; set; }
        public string HashVal { get; set; }
    }

    public class CustomerModel
    {
        public string AcctNo { get; set; }
        public string CustId { get; set; }
        public string MobileNo { get; set; }
        public string Dob { get; set; }
        public string Captcha { get; set; }
        public string PanNo { get; set; }
    }
}