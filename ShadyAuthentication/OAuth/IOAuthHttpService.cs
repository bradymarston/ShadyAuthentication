using System.Threading.Tasks;
using ShadySoft.Authentication;

namespace ShadySoft.Authentication.OAuth
{
    internal interface IOAuthHttpService
    {
        Task<OAuthAccessToken> GetAccessTokenAsync(string oneTimeCode);
        Task<IOAuthUserInfo> GetUserInfoAsync(OAuthAccessToken token);
    }
}