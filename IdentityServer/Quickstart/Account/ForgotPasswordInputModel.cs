namespace IdentityServer.Quickstart.Account
{
    public class ForgotPasswordInputModel
    {
        public string ReturnUrl { get; set; }
        public string Email { get; set; }
        public MailState EmailSent { get; set; }
    }

    public enum MailState
    {
        None, Sent, Error
    }
}