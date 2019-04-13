using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using ShadySoft.Authentication;

namespace ShadySoft.Authentication.OAuth
{
    public class OAuthService
    {
        public ShadyAuthenticationOptions ShadyOptions { get; set; }
        public OAuthService(IOptions<ShadyAuthenticationOptions> shadyOptionsAccessor)
        {
            ShadyOptions = shadyOptionsAccessor?.Value ?? new ShadyAuthenticationOptions();
        }

        public async Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string oneTimeCode, string provider)
        {
            IOAuthHttpService oAuthService;

            switch (provider)
            {
                case ExternalLoginProviders.Facebook:
                    oAuthService = new FacebookHttpService(ShadyOptions);
                    break;
                case ExternalLoginProviders.Google:
                    oAuthService = new GoogleHttpService(ShadyOptions);
                    break;
                case ExternalLoginProviders.Microsoft:
                    oAuthService = new MicrosoftHttpService(ShadyOptions);
                    break;
                default:
                    return null;
            }

            var accessToken = await oAuthService.GetAccessTokenAsync(oneTimeCode);
            if (accessToken == null)
                return null;

            var userInfo = await oAuthService.GetUserInfoAsync(accessToken);
            if (userInfo == null)
                return null;

            var principal = GeneratePrincipal(userInfo, provider);

            return new ExternalLoginInfo(principal, provider, userInfo.Id, ExternalLoginProviders.DisplayName(provider))
            {
                AuthenticationTokens = GenerateAuthenticationTokens(accessToken)
            };
        }

        private ClaimsPrincipal GeneratePrincipal(IOAuthUserInfo userInfo, string provider)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Surname, userInfo.LastName),
                new Claim(ClaimTypes.GivenName, userInfo.FirstName),
                new Claim(ClaimTypes.Name, userInfo.Name),
                new Claim(ClaimTypes.NameIdentifier, userInfo.Id)
            };

            var identity = new ClaimsIdentity(claims, provider, ClaimTypes.NameIdentifier, ClaimTypes.Role);
            return new ClaimsPrincipal(identity);
        }

        private IEnumerable<Microsoft.AspNetCore.Authentication.AuthenticationToken> GenerateAuthenticationTokens(OAuthAccessToken token)
        {
            var authTokens = new List<Microsoft.AspNetCore.Authentication.AuthenticationToken>();

            if (token != null)
            {
                if (!string.IsNullOrWhiteSpace(token.AccessToken))
                    authTokens.Add(new Microsoft.AspNetCore.Authentication.AuthenticationToken
                    {
                        Name = "access_token",
                        Value = token.AccessToken
                    });

                if (!string.IsNullOrEmpty(token.TokenType))
                {
                    authTokens.Add(new Microsoft.AspNetCore.Authentication.AuthenticationToken { Name = "token_type", Value = token.TokenType });
                }

                if (token.ExpiresIn > 0)
                {
                    var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(token.ExpiresIn);
                    authTokens.Add(new Microsoft.AspNetCore.Authentication.AuthenticationToken
                    {
                        Name = "expires_at",
                        Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                    });
                }
            }

            return authTokens;
        }
    }
}
