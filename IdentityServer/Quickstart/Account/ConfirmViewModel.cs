namespace IdentityServer.Quickstart.Account
{
    public class ConfirmViewModel
    {
        public bool ConfirmedMail { get; set; }
        public string Email { get; set; }
        public string ReturnUrl { get; set; }
        public MailState MailSent { get; set; }
    }
}