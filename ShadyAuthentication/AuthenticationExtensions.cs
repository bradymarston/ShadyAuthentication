﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
            builder.Services.AddScoped<ISignInManager<TUser>, Authentication.SignInManager<TUser>>();

            builder.Services.AddDataProtection();

            return builder.AddScheme<ShadyAuthenticationOptions, ShadyAuthenticationHandler<TUser>>(
                authenticationScheme, configureOptions);
        }

        public static TUser GetAuthenticatedUser<TUser>(this Controller controller)
            where TUser : IdentityUser, IUser
        {
            return (TUser)controller.HttpContext.Items["AuthenticatedUser"];
        }
    }
}
