
namespace ShadySoft.Authentication.OAuth
{
    public class OAuthAccessToken
    {
        public string AccessToken { get; set; }
        public int ExpiresIn { get; set; }
        public string Scope { get; set; }
        public string TokenType { get; set; }
        public string IdToken { get; set; }
    }
}
