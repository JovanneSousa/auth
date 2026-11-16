using Auth.Domain.Entities;
using Auth.Domain.Extensions;

namespace Auth.Api.Configuration
{
    public static class SettingsConfig
    {
        public static WebApplicationBuilder AddSettingsConfig(this WebApplicationBuilder builder)
        {
            builder.Services.Configure<AppTokenSettings>(
                builder.Configuration.GetSection("AppTokenSettings"));

            builder.Services.Configure<FrontEndSettings>(
                builder.Configuration.GetSection("FrontEndSettings"));
            return builder;
        }
    }
}
