using Auth.Infra.Data;
using Auth.Infra.Identity;
using Microsoft.AspNetCore.Identity;
using NetDevPack.Security.Jwt.Core.Jwa;

namespace Auth.Configuration
{
    public static class IdentityConfig
    {
        public static WebApplicationBuilder AddIdentityConfig(this WebApplicationBuilder builder)
        {
            builder.Services.AddJwksManager(options => 
                options.Jws = Algorithm.Create(DigitalSignaturesAlgorithm.RsaSsaPssSha256))
                .PersistKeysToDatabaseStore<ApplicationDbContext>();

            builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
                .AddRoles<ApplicationRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();


            var appSettings = builder.Configuration.GetSection("AppTokenSettings");
            builder.Services.Configure<AppTokenSettings>(appSettings);

            return builder;
        }
    }
}
