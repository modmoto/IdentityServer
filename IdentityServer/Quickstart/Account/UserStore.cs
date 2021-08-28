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

        public Task CreateUser(UserAccount userAccount)
        {
            userAccount.Password = userAccount.Password.Sha256();
            return _userAccountRepository.Insert(userAccount);
        }

        public Task<UserAccount> FindByUserEmail(string email)
        {
            return _userAccountRepository.FindByMail(email);
        }
    }
}