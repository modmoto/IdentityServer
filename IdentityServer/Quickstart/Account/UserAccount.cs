using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace IdentityServer.Quickstart.Account
{
    public class UserAccount
    {
        public string UserName { get; set; }
        public string UserEmail { get; set; }
        [BsonId]
        public ObjectId SubjectId { get; set; }
        public string Password { get; set; }
    }
}
    