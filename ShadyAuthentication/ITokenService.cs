using ShadySoft.Authentication.Models;

namespace ShadySoft.Authentication
{
    public interface ITokenService
    {
        AuthenticationToken DecodeTokenString(string tokenString);
        string GenerateTokenString(string userId);
    }
}
