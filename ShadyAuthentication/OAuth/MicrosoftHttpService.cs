using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using ShadySoft.Authentication;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web;

namespace ShadySoft.Authentication.OAuth
{
    public class MicrosoftHttpService : IOAuthHttpService
    {
        public string ProviderId { get; } = "Microsoft";
        public string ProviderDisplayName { get; } = "Microsoft";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _callbackUri;

        public MicrosoftHttpService(string clientId, string clientSecret, string callbackUri)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _callbackUri = callbackUri;
        }

        public async Task<OAuthAccessToken> GetAccessTokenAsync(string oneTimeCode)
        {
            using (HttpClient client = new HttpClient())
            {
                var url = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

                var bodyString = $"client_id={_clientId}";
                bodyString += $"&scope=https%3A%2F%2Fgraph.microsoft.com%2Fuser.read";
                bodyString += $"&code={oneTimeCode}";
                bodyString += $"&redirect_uri={HttpUtility.UrlEncode(_callbackUri)}";
                bodyString += "&grant_type=authorization_code";
                bodyString += $"&client_secret={HttpUtility.UrlEncode(_clientSecret)}";

                var requestContent = new StringContent(bodyString);

                requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");

                var response = await client.PostAsync(url, requestContent);
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

                var response = await client.GetAsync("https://graph.microsoft.com/v1.0/me");
                if (!response.IsSuccessStatusCode)
                    return null;

                var content = await response.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<MicrosoftUserInfo>(content, new JsonSerializerSettings { ContractResolver = new DefaultContractResolver { NamingStrategy = new CamelCaseNamingStrategy() } });
            }
        }
    }
}