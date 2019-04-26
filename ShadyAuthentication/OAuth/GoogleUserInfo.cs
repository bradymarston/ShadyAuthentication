using Newtonsoft.Json;

namespace ShadySoft.Authentication.OAuth
{
    public class GoogleUserInfo : IOAuthUserInfo
    {
        [JsonProperty(PropertyName = "Sub")]
        public string Id { get; set; }
        public string Name { get; set; }
        [JsonProperty(PropertyName = "Given_Name")]
        public string FirstName { get; set; }
        [JsonProperty(PropertyName = "Family_Name")]
        public string LastName { get; set; }
        [JsonProperty(PropertyName = "Profile")]
        public string ProfileUrl { get; set; }
        [JsonProperty(PropertyName = "Picture")]
        public string PictureUrl { get; set; }
        public string Locale { get; set; }
    }
}
