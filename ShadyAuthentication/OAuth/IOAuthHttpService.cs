using System.Threading.Tasks;
using ShadySoft.Authentication;

namespace ShadySoft.Authentication.OAuth
{
    public interface IOAuthHttpService
    {
        string ProviderId { get; }
        string ProviderDisplayName { get; }
        Task<OAuthAccessToken> GetAccessTokenAsync(string oneTimeCode);
        Task<IOAuthUserInfo> GetUserInfoAsync(OAuthAccessToken token);
    }
}