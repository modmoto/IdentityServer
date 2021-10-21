namespace IdentityServer.Quickstart.Account
{
    public class MailInputModel
    {
        public string ReturnUrl { get; set; }
        public string Email { get; set; }
        public MailState EmailSent { get; set; } = MailState.None;
    }

    public enum MailState
    {
        None = 0, Sent = 1, Error = 2
    }
}