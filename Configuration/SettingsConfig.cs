using auth.Infra.Identity;
using auth.Infra.MessageBus;

namespace auth.Configuration
{
    public static class SettingsConfig
    {
        public static WebApplicationBuilder AddSettingsConfig(this WebApplicationBuilder builder)
        {
            builder.Services.Configure<RabbitSettings>(
                builder.Configuration.GetSection("RabbitSettings"));

            builder.Services.Configure<JwtSettings>(
                builder.Configuration.GetSection("JwtSettings"));

            return builder;
        }
    }
}
