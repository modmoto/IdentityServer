using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityServer.Quickstart.Mail
{
    public class MailModelBase : IMail
    {
        public MailModelBase(string subject)
        {
            Subject = subject;
        }

        protected static string Encode(string resetToken)
        {
            var tokenGeneratedBytes = Encoding.UTF8.GetBytes(resetToken);
            var codeEncoded = WebEncoders.Base64UrlEncode(tokenGeneratedBytes);
            return codeEncoded;
        }

        public string Subject { get; }
    }
}