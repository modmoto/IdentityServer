using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Quickstart.Account
{
    public class RegisterInputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string Name { get; set; }
        public string ReturnUrl { get; set; }
    }
}