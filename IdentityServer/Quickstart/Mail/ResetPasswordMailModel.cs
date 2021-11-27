using System;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityServer.Quickstart.Mail
{
    public class ResetPasswordMailModel : MailModel
    {
        public string ResetPasswordLink { get; }

        public ResetPasswordMailModel(string resetCode, string returnUrl, string mail)
        {
            var codeEncoded = Encode(resetCode);
            var returnUrlEncoded = Encode(returnUrl);
            var mailEncoded = Encode(mail);
            ResetPasswordLink = $"https://{Environment.GetEnvironmentVariable("IDENTITY_BASE_URI")}/Account/ResetPassword?resetToken={codeEncoded}&returnUrl={returnUrlEncoded}&email={mailEncoded}";
        }
    }

    public class MailModel
    {
        protected static string Encode(string resetToken)
        {
            var tokenGeneratedBytes = Encoding.UTF8.GetBytes(resetToken);
            var codeEncoded = WebEncoders.Base64UrlEncode(tokenGeneratedBytes);
            return codeEncoded;
        }
    }
}