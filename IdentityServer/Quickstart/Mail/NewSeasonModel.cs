namespace IdentityServer.Quickstart.Mail
{
    public class NewSeasonModel : MailModelBase
    {
        public NewSeasonModel(string listSubmissionDeadline, string seasonStart, string userName) : base($"Register for the next season until {listSubmissionDeadline}")
        {
            ListSubmissionDeadline = listSubmissionDeadline;
            SeasonStart = seasonStart;
            Name = userName;
        }

        public string ListSubmissionDeadline { get; }
        public string SeasonStart { get; }
        public string Name { get; }
    }
}