using System.Threading.Tasks;
using Duende.IdentityServer.Models;

namespace IdentityServer.Quickstart.Account
{
    public class UserStore
    {
        private readonly UserAccountRepository _userAccountRepository;

        public UserStore(UserAccountRepository userAccountRepository)
        {
            _userAccountRepository = userAccountRepository;
        }
        
        public async Task<bool> ValidateCredentials(string email, string password)
        {
            var user = await _userAccountRepository.FindByMail(email);
            return user.Password == password.Sha256();
        }

        public async Task<bool> CreateUser(UserAccount userAccount)
        {
            var user = await _userAccountRepository.FindByMail(userAccount.UserEmail);
            if (user == null)
            {
                userAccount.Password = userAccount.Password.Sha256();
                await _userAccountRepository.Insert(userAccount);
                return true;
            }

            return false;
        }

        public Task<UserAccount> FindByUserEmail(string email)
        {
            return _userAccountRepository.FindByMail(email);
        }
    }
}