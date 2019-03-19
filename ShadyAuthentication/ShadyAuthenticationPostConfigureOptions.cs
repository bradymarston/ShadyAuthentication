using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationPostConfigureOptions : IPostConfigureOptions<ShadyAuthenticationOptions>
    {
        public void PostConfigure(string name, ShadyAuthenticationOptions options)
        {
            if (string.IsNullOrEmpty(options.Realm))
                throw new InvalidOperationException("Realm must be provided in options");
        }
    }
}
