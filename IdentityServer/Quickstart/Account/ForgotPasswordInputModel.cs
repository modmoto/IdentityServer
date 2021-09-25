namespace IdentityServer.Quickstart.Account
{
    public class ForgotPasswordInputModel
    {
        public string ReturnUrl { get; set; }
        public string Email { get; set; }
        public bool EmailSent { get; set; }
    }
}