
namespace ShadySoft.Authentication.OAuth
{
    public interface IOAuthUserInfo
    {
        string Id { get; }
        string Name { get; }
        string FirstName { get; }
        string LastName { get; }
    }
}
