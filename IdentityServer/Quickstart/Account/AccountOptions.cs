using System;

namespace IdentityServer.Quickstart.Account
{
    public class AccountOptions
    {
        public static bool AllowLocalLogin = true;

        public static bool ShowLogoutPrompt = true;
        public static bool AutomaticRedirectAfterSignOut = false;

        public static string InvalidCredentialsErrorMessage = "Invalid username or password";
    }
}
