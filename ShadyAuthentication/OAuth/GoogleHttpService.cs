using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using ShadySoft.Authentication;
using System.Net.Http;
using System.Threading.Tasks;

namespace ShadySoft.Authentication.OAuth
{
    public class GoogleHttpService : IOAuthHttpService
    {
        public string ProviderId { get; } = "Google";
        public string ProviderDisplayName { get; } = "Google";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _callbackUri;

        public GoogleHttpService(string clientId, string clientSecret, string callbackUri)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _callbackUri = callbackUri;
        }

        public async Task<OAuthAccessToken> GetAccessTokenAsync(string oneTimeCode)
        {
            using (HttpClient client = new HttpClient())
            {
                var url = "https://www.googleapis.com/oauth2/v4/token";
                url += $"?client_id={_clientId}";
                url += $"&redirect_uri={_callbackUri}";
                url += $"&client_secret={_clientSecret}";
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