using Auth.Infra.Notifications;
using Auth.Application.Repositories;
using Auth.Application.Services;

namespace Auth.Api.Configuration;

public static class DiConfig
{
    public static async Task<WebApplicationBuilder> AddDiConfig(this WebApplicationBuilder builder)
    {
        builder.Services.AddScoped<INotificador, Notificador>();
        builder.Services.AddScoped<IAuthRepository, AuthRepository>();
        builder.Services.AddScoped<IAuthService, AuthService>();

        return builder;
    }
}
