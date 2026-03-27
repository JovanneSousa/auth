using Auth.Infra.Data;
using Auth.Infra.Identity;
using Microsoft.AspNetCore.Identity;
using NetDevPack.Security.Jwt.Core.Jwa;
using System.Text;

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

            var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
            if (string.IsNullOrEmpty(jwtSettings?.Segredo))
                throw new InvalidOperationException("Segredo JWT não configurado.");

            var key = Encoding.ASCII.GetBytes(jwtSettings.Segredo);

            //builder.Services.AddAuthentication(o =>
            //{
            //    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //}).AddJwtBearer(o =>
            //{
            //    o.RequireHttpsMetadata = true;
            //    o.SaveToken = true;
            //    o.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        IssuerSigningKey = new SymmetricSecurityKey(key),
            //        ValidateIssuer = true,
            //        ValidateAudience = true,
            //        ValidAudience = jwtSettings.Audiencia,
            //        ValidIssuer = jwtSettings.Emissor
            //    };
            //});

            return builder;
        }
    }
}
