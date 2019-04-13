using System;

namespace ShadySoft.Authentication.Models
{
    public class AuthenticationToken
    {
        public string UserId { get; set; }
        public DateTime Issued { get; set; }
        public string SecurityStamp { get; set; }
    }
}
