
namespace ShadySoft.Authentication.OAuth
{
    public static class ExternalLoginProviders
    {
        public const string Facebook = "Facebook";
        public const string Google = "Google";
        public const string Microsoft = "Microsoft";

        public static string DisplayName(string provider)
        {
            switch (provider)
            {
                case Facebook:
                    return "Facebook";
                case Google:
                    return "Google";
                case Microsoft:
                    return "Microsoft";
                default:
                    return "Not Found";
            }
        }
    }
}
