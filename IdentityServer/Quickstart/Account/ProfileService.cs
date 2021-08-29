using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;

namespace IdentityServer.Quickstart.Account
{
    public class ProfileService : IProfileService
    {
        private readonly UserAccountRepository _userRepository;

        public ProfileService(UserAccountRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var email = context.Subject.Identity.Name;
            if (!string.IsNullOrEmpty(email))
            {
                var user = await _userRepository.FindByMail(email);

                if (user != null)
                {
                    var claims = new List<Claim>
                    {
                        new(JwtClaimTypes.Name, user.UserEmail),
                        new(JwtClaimTypes.GivenName, user.UserName),
                        new(JwtClaimTypes.Email, user.UserEmail)
                    };
                    context.IssuedClaims = claims;
                }
            }
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }
}