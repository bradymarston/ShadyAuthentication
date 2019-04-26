using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using ShadySoft.Authentication;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace ShadySoft.Authentication.OAuth
{
    public class FacebookHttpService : IOAuthHttpService
    {
        public string ProviderId { get; } = "Facebook";
        public string ProviderDisplayName { get; } = "Facebook";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _callbackUri;

        public FacebookHttpService(string clientId, string clientSecret, string callbackUri)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _callbackUri = callbackUri;
        }


        public async Task<OAuthAccessToken> GetAccessTokenAsync(string oneTimeCode)
        {
            using (HttpClient client = new HttpClient())
            {
                var url = "https://graph.facebook.com/v3.2/oauth/access_token";
                url += $"?client_id={_clientId}";
                url += $"&redirect_uri={_callbackUri}";
                url += $"&client_secret={_clientSecret}";
                url += $"&code={oneTimeCode}";

                var result = await client.GetAsync(url);
                if (!result.IsSuccessStatusCode)
                    return null;

                var content = await result.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<OAuthAccessToken>(content, new JsonSerializerSettings { ContractResolver = new DefaultContractResolver { NamingStrategy = new SnakeCaseNamingStrategy() } });
            }
        }

        private async Task<FacebookAccessTokenInfo> GetAccessTokenInfo(OAuthAccessToken token)
        {
            using (HttpClient client = new HttpClient())
            {
                var url = "https://graph.facebook.com/debug_token";
                url += $"?input_token={token.AccessToken}";
                url += $"&access_token={token.AccessToken}";

                var result = await client.GetAsync(url);
                if (!result.IsSuccessStatusCode)
                    return null;

                var content = await result.Content.ReadAsStringAsync();

                var response = JsonConvert.DeserializeObject<FacebookAccessTokenInfoResponse>(content, new JsonSerializerSettings { ContractResolver = new DefaultContractResolver { NamingStrategy = new SnakeCaseNamingStrategy() } });

                return response.Data;
            }
        }

        private async Task<IOAuthUserInfo> GetUserInfoAsync(string userId, OAuthAccessToken token)
        {
            using (HttpClient client = new HttpClient())
            {
                var url = $"https://graph.facebook.com/v3.2/{userId}";
                url += $"?access_token={token.AccessToken}";
                url += "&fields=first_name,last_name,name,picture";
                var result = await client.GetAsync(url);
                if (!result.IsSuccessStatusCode)
                    return null;

                var content = await result.Content.ReadAsStringAsync();

                return JsonConvert.DeserializeObject<FacebookUserInfo>(content, new JsonSerializerSettings { ContractResolver = new DefaultContractResolver { NamingStrategy = new SnakeCaseNamingStrategy() } });
            }
        }

        public async Task<IOAuthUserInfo> GetUserInfoAsync(OAuthAccessToken token)
        {
            var facebookInfo = await GetAccessTokenInfo(token);
            if (facebookInfo == null)
                return null;

            return await GetUserInfoAsync(facebookInfo.UserId, token);
        }

        private class FacebookAccessTokenInfoResponse
        {
            public FacebookAccessTokenInfo Data { get; set; } = new FacebookAccessTokenInfo();
        }

        private class FacebookAccessTokenInfo
        {
            public string AppId { get; set; } = "";
            public string Type { get; set; } = "";
            public string Application { get; set; } = "";
            [JsonConverter(typeof(UnixDateTimeConverter))]
            public DateTime DataAccessExpiresAt { get; set; }
            [JsonConverter(typeof(UnixDateTimeConverter))]
            public DateTime ExpiresAt { get; set; }
            public bool IsValid { get; set; }
            [JsonConverter(typeof(UnixDateTimeConverter))]
            public DateTime IssuedAt { get; set; }
            public string[] Scopes { get; set; } = { };
            public string UserId { get; set; } = "";
        }
    }
}