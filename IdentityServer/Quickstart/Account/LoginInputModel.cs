using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Quickstart.Account
{
    public class LoginInputModel
    {
        [Required]
        public string Password { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        public bool RememberLogin { get; set; }
        public bool ConfirmedMail { get; set; }
        public string ReturnUrl { get; set; }
    }
}