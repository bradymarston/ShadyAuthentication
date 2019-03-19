using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ShadySoft.Authentication.Models
{
    public class SignInResult : Microsoft.AspNetCore.Identity.SignInResult
    {
        public bool ConfirmCredential { get; }
        public string Token { get; }

        public SignInResult(string token = "", bool succeeded = false, bool isLockedOut = false, bool isNotAllowed = false, bool requiresTwoFactor = false, bool confirmCredential = false)
        {
            Succeeded = !string.IsNullOrWhiteSpace(token) || succeeded;
            IsLockedOut = isLockedOut;
            IsNotAllowed = isNotAllowed;
            RequiresTwoFactor = requiresTwoFactor;
            ConfirmCredential = confirmCredential;
            Token = token;
        }

        new public static SignInResult Success => new SignInResult(succeeded: true);
        new public static SignInResult LockedOut => new SignInResult(isLockedOut: true);
        new public static SignInResult NotAllowed => new SignInResult(isNotAllowed: true);
        new public static SignInResult TwoFactorRequired => new SignInResult(requiresTwoFactor: true);
        public static SignInResult ConfirmationRequired => new SignInResult(confirmCredential: true);
        new public static SignInResult Failed => new SignInResult();
    }
}
