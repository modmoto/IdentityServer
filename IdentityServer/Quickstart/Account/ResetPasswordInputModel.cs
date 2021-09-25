using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Quickstart.Account
{
    public class ResetPasswordInputModel
    {
        public string ReturnUrl { get; set; }
        public string Email { get; set; }
        [Required]
        public string NewPassword { get; set; }
        [Required]
        public string RepeatPassword { get; set; }

        public string PasswordResetToken { get; set; }
    }
}