using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using ShadySoft.Authentication.Models;

namespace ShadySoft.Authentication
{
    public interface ISignInManager<TUser> where TUser : IdentityUser, IUser
    {
        IdentityOptions Options { get; }

        Task<bool> CheckCredentialConfirmationAsync(TUser user, CredentialType credentialType);
        Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure);
        Task<bool> IsTwoFactorClientRememberedAsync(TUser user);
        Task<(string TokenString, SignInResult Result)> PasswordSignInAsync(string userName, string password, bool lockoutOnFailure);
        Task<(string TokenString, SignInResult Result)> EmailPasswordSignInAsync(string email, string password, bool lockoutOnFailure);
        Task<(string TokenString, SignInResult Result)> PasswordSignInAsync(TUser user, string password, bool lockoutOnFailure);
        string SignIn(TUser user);
        Task SignOutAsync(TUser user);
    }
}