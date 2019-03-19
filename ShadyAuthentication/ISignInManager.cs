using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using ShadySoft.Authentication.Models;

namespace ShadySoft.Authentication
{
    public interface ISignInManager<TUser> where TUser : IdentityUser, IUser
    {
        IdentityOptions Options { get; }

        Task<bool> CheckCredentialConfirmationAsync(TUser user, CredentialType credentialType);
        Task<Models.SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure);
        Task<bool> IsTwoFactorClientRememberedAsync(TUser user);
        Task<Models.SignInResult> PasswordSignInAsync(string userName, string password, bool lockoutOnFailure);
        Task<Models.SignInResult> EmailPasswordSignInAsync(string email, string password, bool lockoutOnFailure);
        Task<Models.SignInResult> PasswordSignInAsync(TUser user, string password, bool lockoutOnFailure);
        string SignIn(TUser user);
        Task SignOutAsync(TUser user);
    }
}