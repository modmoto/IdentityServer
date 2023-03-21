using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AspNetCore.Identity.Mongo.Model;
using IdentityServer.Quickstart.Account;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Logging;
using MimeKit;
using MongoDB.Driver;

namespace IdentityServer.Quickstart.Mail
{
    public interface IMailService
    {
        Task<MailState> SendMail(string email, NewAccountMail mailBody);
        Task<MailState> SendMail(string email, ResetPasswordMailModel mailBody);
        Task<MailState> SendNewSeasonMail(string listDeadline, string seasonStart);
    }

    public class MailService : IMailService
    {
        private readonly IMailRenderer _emailEngine;
        private readonly ILogger _logger;
        private readonly IMongoCollection<MongoUser> _userStore;
        private readonly bool _isTestMode = string.Equals(Environment.GetEnvironmentVariable("IS_TEST_MODE"), "true", StringComparison.OrdinalIgnoreCase);

        public MailService(IMailRenderer emailEngine, ILogger<IMailService> logger, IMongoCollection<MongoUser> userStore)
        {
            _emailEngine = emailEngine;
            _logger = logger;
            _userStore = userStore;
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
                return await SendMailForReal(email, email, mailBody.Subject, false, "/Views/Emails/ResetPasswordAccountMail.cshtml", mailBody);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Mail sending failed");
                return MailState.Error;
            }
        }

        public async Task<MailState> SendNewSeasonMail(string listDeadline, string seasonStart)
        {
            var allUsers = await _userStore.Find(user => true).ToListAsync();
            for (var index = 0; index < allUsers.Count; index++)
            {
                var user = allUsers[index];
                var userName = user.Claims.FirstOrDefault(c => c.ClaimType == "given_name")?.ClaimValue;
                var newSeasonModel = new NewSeasonModel(listDeadline, seasonStart, userName);
                try
                {
                    await SendMailForReal(user.Email, userName, newSeasonModel.Subject, true, "/Views/Emails/NewSeasonMail.cshtml", newSeasonModel);
                    _logger.LogInformation($"Mail {index + 1}/{allUsers.Count} sent to: {user.Email}");
                }
                catch (Exception e)
                {
                    _logger.LogError($"Mail {index + 1}/{allUsers.Count} failed to: {user.Email}", e.Message);
                    return MailState.Error;
                }
            }

            return MailState.Sent;
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