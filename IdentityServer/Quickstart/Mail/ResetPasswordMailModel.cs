﻿using System;

namespace IdentityServer.Quickstart.Mail
{
    public class ResetPasswordMailModel : MailModelBase
    {
        public string ResetPasswordLink { get; }

        public ResetPasswordMailModel(string resetCode, string returnUrl, string mail) : base("Reset password")
        {
            var codeEncoded = Encode(resetCode);
            var returnUrlEncoded = Encode(returnUrl);
            var mailEncoded = Encode(mail);
            ResetPasswordLink = $"https://{Environment.GetEnvironmentVariable("IDENTITY_BASE_URI")}/Account/ResetPassword?resetToken={codeEncoded}&returnUrl={returnUrlEncoded}&email={mailEncoded}";
        }
    }
}