using Microsoft.AspNetCore.Authentication;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Realm { get; set; }
    }
}
