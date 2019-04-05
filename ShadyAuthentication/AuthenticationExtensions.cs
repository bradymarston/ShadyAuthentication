using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ShadySoft.Authentication.OAuth;
using System;

namespace ShadySoft.Authentication
{
    public static class AuthenticationExtensions
    {
        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder)
            where TUser : IdentityUser, IUser
        {
            return AddShady<TUser>(builder, ShadyAuthenticationDefaults.AuthenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder, string authenticationScheme)
            where TUser : IdentityUser, IUser
        {
            return AddShady<TUser>(builder, authenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder, Action<ShadyAuthenticationOptions> configureOptions)
            where TUser : IdentityUser, IUser
        {
            return AddShady<TUser>(builder, ShadyAuthenticationDefaults.AuthenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder, string authenticationScheme, Action<ShadyAuthenticationOptions> configureOptions)
            where TUser : IdentityUser, IUser
        {
            builder.Services.AddSingleton<IPostConfigureOptions<ShadyAuthenticationOptions>, ShadyAuthenticationPostConfigureOptions>();
            builder.Services.AddScoped<ITokenService, TokenService>();
            builder.Services.AddScoped<ISignInManager<TUser>, SignInManager<TUser>>();
            builder.Services.AddScoped<OAuthService>();

            builder.Services.AddDataProtection();

            builder.Services.Configure(configureOptions);

            return builder.AddScheme<ShadyAuthenticationOptions, ShadyAuthenticationHandler<TUser>>(
                authenticationScheme, configureOptions);
        }

        public static TUser GetAuthorizedUser<TUser>(this HttpContext context)
            where TUser : IdentityUser, IUser
        {
            var user = (TUser)context.Items["AuthenticatedUser"];

            if (user == null)
                throw new Exception("No user authenticated. GetAuthenticatedUser should only be called on actions with an Authorized attribute.");

            return user;
        }
    }
}
