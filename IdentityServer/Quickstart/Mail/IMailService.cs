using System;
using System.Threading.Tasks;
using IdentityServer.Quickstart.Account;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace IdentityServer.Quickstart.Mail
{
    public interface IMailService
    {
        Task<MailState> SendMail<T>(string email, string name, bool sendBccCopy, T mailBody) where T : IMail;
    }

    public class MailService : IMailService
    {
        private readonly IMailRenderer _emailEngine;
        private readonly ILogger _logger;
        private readonly bool _isTestMode = string.Equals(Environment.GetEnvironmentVariable("IS_TEST_MODE"), "true", StringComparison.OrdinalIgnoreCase);


        public MailService(IMailRenderer emailEngine, ILogger<IMailService> logger)
        {
            _emailEngine = emailEngine;
            _logger = logger;
        }
        
        public async Task<MailState> SendMail<T>(string email, string name, bool sendBccCopy, T mailBody) where T : IMail
        {
            try
            {
                var emailText = await _emailEngine.RenderViewToStringAsync("/Views/Emails/NewAccountMail.cshtml", mailBody);
                var mailMessage = new MimeMessage();
                mailMessage.From.Add(new MailboxAddress("Fading Flame", "info@fading-flame.com"));
                if (_isTestMode)
                {
                    mailMessage.To.Add(new MailboxAddress("simonheiss87@gmail.com", "simonheiss87@gmail.com"));
                }
                else
                {
                    mailMessage.To.Add(new MailboxAddress(name ?? email, email));
                }

                if (sendBccCopy)
                {
                    mailMessage.Bcc.Add(new MailboxAddress("Simon", "simonheiss87@gmail.com"));                    
                }
                
                mailMessage.Subject = mailBody.Subject;
                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = emailText
                };

                mailMessage.Body = bodyBuilder.ToMessageBody();

                using var smtpClient = new SmtpClient();
                await smtpClient.ConnectAsync("smtp.strato.de", 465, true);
                await smtpClient.AuthenticateAsync("info@fading-flame.com", Environment.GetEnvironmentVariable("MAIL_PASSWORD"));
                await smtpClient.SendAsync(mailMessage);
                await smtpClient.DisconnectAsync(true);

                return MailState.Sent;
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Mail sending failed");
                return MailState.Error;
            }
        }
    }

    public interface IMail
    {
        public string Subject { get; }
    }
}