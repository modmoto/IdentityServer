using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Quickstart.Account
{
    public class RegisterInputModel : LoginInputModel
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public string RepeatPassword { get; set; }
    }
}