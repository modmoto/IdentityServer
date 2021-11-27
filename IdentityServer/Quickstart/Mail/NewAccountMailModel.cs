using System;

namespace IdentityServer.Quickstart.Mail
{
    public class NewAccountMail : MailModel
    {
        public string Name { get; }
        public string VerifyLink { get; }

        public NewAccountMail(string name, string newAccountToken, string returnUrl, string email)
        {
            Name = name;
            var codeEncoded = Encode(newAccountToken);
            var returnUrlEncoded = Encode(returnUrl);
            var mailEncoded = Encode(email);
            VerifyLink = $"https://{Environment.GetEnvironmentVariable("IDENTITY_BASE_URI")}/Account/ConfirmMail?confirmToken={codeEncoded}&returnUrl={returnUrlEncoded}&email={mailEncoded}";
        }
    }
}