using Microsoft.AspNetCore.Authentication;
using ShadySoft.Authentication.OAuth;
using System.Collections.Generic;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Realm { get; set; }
        public List<IOAuthHttpService> ExternalLoginProviders { get; set; }
    }
}
