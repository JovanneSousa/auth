using Auth.Infra.Identity;
using Auth.Domain.Entities;

namespace Auth.Api.Configuration
{
    public static class SettingsConfig
    {
        public static WebApplicationBuilder AddSettingsConfig(this WebApplicationBuilder builder)
        {
            builder.Services.Configure<JwtSettings>(
                builder.Configuration.GetSection("JwtSettings"));

            builder.Services.Configure<FrontEndSettings>(
                builder.Configuration.GetSection("FrontEndSettings"));
            return builder;
        }
    }
}
