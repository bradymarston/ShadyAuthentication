using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using ShadySoft.Authentication;
using System.Net.Http;
using System.Threading.Tasks;

namespace ShadySoft.Authentication.OAuth
{
    internal class GoogleHttpService : IOAuthHttpService
    {
        private readonly ShadyAuthenticationOptions _shadyOptions;

        public GoogleHttpService(ShadyAuthenticationOptions shadyOptions)
        {
            _shadyOptions = shadyOptions;
        }

        public async Task<OAuthAccessToken> GetAccessTokenAsync(string oneTimeCode)
        {
            using (HttpClient client = new HttpClient())
            {
                var url = "https://www.googleapis.com/oauth2/v4/token";
                url += $"?client_id={_shadyOptions.GoogleAppId}";
                url += $"&redirect_uri={_shadyOptions.GoogleCallbackUri}";
                url += $"&client_secret={_shadyOptions.GoogleAppSecret}";
                url += $"&code={oneTimeCode}";
                url += "&grant_type=authorization_code";

                var response = await client.PostAsync(url, new StringContent(""));
                if (!response.IsSuccessStatusCode)
                    return null;

                var content = await response.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<OAuthAccessToken>(content, new JsonSerializerSettings { ContractResolver = new DefaultContractResolver { NamingStrategy = new SnakeCaseNamingStrategy() } });
            }
        }

        public async Task<IOAuthUserInfo> GetUserInfoAsync(OAuthAccessToken token)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", $"{token.TokenType} {token.AccessToken}");

                var response = await client.GetAsync("https://openidconnect.googleapis.com/v1/userinfo");
                if (!response.IsSuccessStatusCode)
                    return null;

                var content = await response.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<GoogleUserInfo>(content, new JsonSerializerSettings { ContractResolver = new DefaultContractResolver { NamingStrategy = new SnakeCaseNamingStrategy() } });
            }
        }
    }
}