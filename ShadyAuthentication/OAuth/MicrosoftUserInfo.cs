using Newtonsoft.Json;

namespace ShadySoft.Authentication.OAuth
{
    public class MicrosoftUserInfo : IOAuthUserInfo
    {
        public string Id { get; set; }
        [JsonProperty(PropertyName = "DisplayName")]
        public string Name { get; set; }
        [JsonProperty(PropertyName = "GivenName")]
        public string FirstName { get; set; }
        [JsonProperty(PropertyName = "Surname")]
        public string LastName { get; set; }
    }
}
