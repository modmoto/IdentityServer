using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using IdentityServer.Quickstart.Account;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Logging;
using MimeKit;
using MimeKit.Utils;

namespace IdentityServer.Quickstart.Mail
{
    public interface IMailService
    {
        Task<MailState> SendMail(string email, NewAccountMail mailBody);
        Task<MailState> SendMail(string email, ResetPasswordMailModel mailBody);
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
        
        public async Task<MailState> SendMail(string email, NewAccountMail mailBody)
        {
            try
            {
                return await SendMailForReal(email, mailBody.Name, mailBody.Subject, true, "/Views/Emails/NewAccountMail.cshtml", mailBody);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Mail sending failed");
                return MailState.Error;
            }
        }

        public async Task<MailState> SendMail(string email, ResetPasswordMailModel mailBody)
        {
            try
            {
                return await SendMailForReal(email, email, mailBody.Subject, true, "/Views/Emails/ResetPasswordAccountMail.cshtml", mailBody);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Mail sending failed");
                return MailState.Error;
            }
        }

        private async Task<MailState> SendMailForReal<T>(string email, string name, string subject, bool sendBccCopy,
            string emailPath, T mailBody) where T : MailModelBase
        {
            var mailMessage = new MimeMessage();
            var bodyBuilder = new BodyBuilder();
            
            var pathImage = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Views/Emails/logo_ligismall.jpg");
            var image = await bodyBuilder.LinkedResources.AddAsync(pathImage);
            image.ContentId = "vertical_logo";
            
            var emailText = await _emailEngine.RenderViewToStringAsync(emailPath, mailBody);

            mailMessage.From.Add(new MailboxAddress("Fading Flame", "info@fading-flame.com"));
            if (_isTestMode)
            {
                mailMessage.To.Add(new MailboxAddress("simonheiss87@gmail.com", "simonheiss87@gmail.com"));
            }
            else
            {
                mailMessage.To.Add(new MailboxAddress(name, email));
            }

            if (sendBccCopy)
            {
                mailMessage.Bcc.Add(new MailboxAddress("Simon", "simonheiss87@gmail.com"));
            }

            mailMessage.Subject = subject;
            bodyBuilder.HtmlBody = emailText;
            
            mailMessage.Body = bodyBuilder.ToMessageBody();

            using var smtpClient = new SmtpClient();
            await smtpClient.ConnectAsync("smtp.strato.de", 465, true);
            await smtpClient.AuthenticateAsync("info@fading-flame.com", Environment.GetEnvironmentVariable("MAIL_PASSWORD"));
            await smtpClient.SendAsync(mailMessage);
            await smtpClient.DisconnectAsync(true);

            return MailState.Sent;
        }
    }
}