using System;

namespace IdentityServer.Quickstart.Mail
{
    public class NewAccountMail : MailModelBase
    {
        public string Name { get; }
        public string VerifyLink { get; }

        public NewAccountMail(string name, string newAccountToken, string returnUrl, string email) : base("Confirm registration on fading-flame.com")
        {
            Name = name;
            var codeEncoded = Encode(newAccountToken);
            var returnUrlEncoded = Encode(returnUrl);
            var mailEncoded = Encode(email);
            VerifyLink = $"https://{Environment.GetEnvironmentVariable("IDENTITY_BASE_URI")}/Account/ConfirmMail?confirmToken={codeEncoded}&returnUrl={returnUrlEncoded}&email={mailEncoded}";
        }
    }
}