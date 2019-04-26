using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace ShadySoft.Authentication.OAuth
{
    public static class OAuthExtensions
    {
        public static string GetExternalLoginClientId(this IConfiguration configuration, string providerId)
        {
            return configuration.GetSection("ExternalLoginProviderOptions").GetSection(providerId).GetValue<string>("ClientId");
        }

        public static string GetExternalLoginClientSecret(this IConfiguration configuration, string providerId)
        {
            return configuration.GetSection("ExternalLoginProviderOptions").GetSection(providerId).GetValue<string>("ClientSecret");
        }

        public static string GetExternalLoginCallbackUri(this IConfiguration configuration)
        {
            return configuration.GetSection("ExternalLoginProviderOptions").GetValue<string>("CallbackUri");
        }
    }
}
