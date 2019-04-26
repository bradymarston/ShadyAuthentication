using Newtonsoft.Json;

namespace ShadySoft.Authentication.OAuth
{
    public class FacebookUserInfo : IOAuthUserInfo
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PictureUrl { get => Picture.Data.Url; }
        public FacebookPicture Picture { get; set; }
        [JsonProperty(PropertyName ="Link")]
        public string ProfileUrl { get; set; }
        public string Locale { get; set; }

        public class FacebookPictureData
        {
            public string Url { get; set; }
            public int Width { get; set; }
            public int Height { get; set; }
            public bool IsSilhouette { get; set; }
        }

        public class FacebookPicture
        {
            public FacebookPictureData Data { get; set; }
        }
    }
}
