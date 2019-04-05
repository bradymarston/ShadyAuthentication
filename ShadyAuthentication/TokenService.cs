using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;
using ShadySoft.Authentication.Models;

namespace ShadySoft.Authentication
{
    public class TokenService : ITokenService
    {
        private readonly IDataProtectionProvider _protectionProvider;

        public TokenService(IDataProtectionProvider protectionProvider)
        {
            _protectionProvider = protectionProvider;
        }

        public AuthenticationToken DecodeTokenString(string tokenString)
        {
            var decryptedTokenString = "";

            try
            {
                var protector = _protectionProvider.CreateProtector("UserToken");
                decryptedTokenString = protector.Unprotect(tokenString);
            }
            catch (CryptographicException)
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(decryptedTokenString))
                return null;

            return JsonConvert.DeserializeObject<AuthenticationToken>(decryptedTokenString);
        }

        public string GenerateTokenString(string userId)
        {
            var token = new AuthenticationToken() { UserId = userId, Issued = DateTime.UtcNow };

            var protector = _protectionProvider.CreateProtector("UserToken");
            return protector.Protect(JsonConvert.SerializeObject(token));
        }
    }
}
