
namespace ShadySoft.Authentication.OAuth
{
    public static class ExternalLoginProviders
    {
        public const string Facebook = "Facebook";
        public const string Google = "Google";
        public static string DisplayName(string provider)
        {
            switch (provider)
            {
                case Facebook:
                    return "Facebook";
                case Google:
                    return "Google";
                default:
                    return "Not Found";
            }
        }
    }
}
