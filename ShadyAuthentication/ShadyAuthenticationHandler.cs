using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationHandler<TUser> : AuthenticationHandler<ShadyAuthenticationOptions>
        where TUser : IdentityUser, IUser
    {
        private readonly ITokenService _tokenService;
        private readonly UserManager<TUser> _userManager;

        public ShadyAuthenticationHandler(
            IOptionsMonitor<ShadyAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ITokenService tokenService,
            UserManager<TUser> userManager)
            : base(options, logger, encoder, clock)
        {
            _tokenService = tokenService;
            _userManager = userManager;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.NoResult();

            if (!AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"], out AuthenticationHeaderValue headerValue))
            {
                return AuthenticateResult.NoResult();
            }

            if (headerValue.Scheme != ShadyAuthenticationDefaults.AuthenticationScheme)
                return AuthenticateResult.NoResult();
                    
            var token = _tokenService.DecodeTokenString(headerValue.Parameter);
            if (token is null)
                return AuthenticateResult.Fail("Invalid authentication header");

            var user = await _userManager.FindByIdAsync(token.UserId);
            if (user is null)
                return AuthenticateResult.Fail("User in authentication header cannot be found");

            if (token.Issued < user.TokensInvalidBefore)
                return AuthenticateResult.Fail("Token is no longer valid");

            var ticket = await BuildTicketAsync(user);

            Context.Items.Add("AuthenticatedUser", user);

            return AuthenticateResult.Success(ticket);
        }

        private async Task<AuthenticationTicket> BuildTicketAsync(TUser user)
        {
            var claims = new[] {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var identity = new ClaimsIdentity(claims, ShadyAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);

            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
            }

            var principal = new ClaimsPrincipal(identity);
            return new AuthenticationTicket(principal, ShadyAuthenticationDefaults.AuthenticationScheme);
        }
    }
}