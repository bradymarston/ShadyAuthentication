using Microsoft.AspNetCore.Authentication;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Realm { get; set; }
        public string FasebookAppSecret { get; set; }
        public string FacebookAppId { get; set; }
        public string ExternalLoginCallbackUri { get; set; }
        public string GoogleAppSecret { get; set; }
        public string GoogleAppId { get; set; }
        public string MicrosoftAppSecret { get; set; }
        public string MicrosoftAppId { get; set; }
    }
}
