using System;

namespace ShadySoft.Authentication
{
    public interface IUser
    {
        DateTime TokensInvalidBefore { get; set; }
    }
}
