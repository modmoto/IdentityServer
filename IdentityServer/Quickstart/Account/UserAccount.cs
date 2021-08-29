using MongoDB.Bson.Serialization.Attributes;

namespace IdentityServer.Quickstart.Account
{
    public class UserAccount
    {
        public string UserName { get; set; }
        [BsonId]
        public string UserEmail { get; set; }
        public string Password { get; set; }
    }
}
    