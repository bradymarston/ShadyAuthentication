
namespace ShadySoft.Authentication.OAuth
{
    internal interface IOAuthUserInfo
    {
        string Id { get; }
        string Name { get; }
        string FirstName { get; }
        string LastName { get; }
        string PictureUrl { get; }
        string ProfileUrl { get; }
        string Locale { get; }
    }
}
