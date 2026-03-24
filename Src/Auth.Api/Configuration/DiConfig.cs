using Auth.Infra.Interfaces;
using Auth.Infra.Notifications;
using Auth.Infra.Repositories;
using Auth.Application.Services;
using Auth.Domain.Interfaces;

namespace Auth.Api.Configuration;

public static class DiConfig
{
    public static async Task<WebApplicationBuilder> AddDiConfig(this WebApplicationBuilder builder)
    {
        builder.Services.AddScoped<INotificador, Notificador>();
        builder.Services.AddScoped<IAuthRepository, AuthRepository>();
        builder.Services.AddScoped<IAuthService, AuthService>();
        builder.Services.AddScoped<ISystemRepository, SystemRepository>();
        builder.Services.AddScoped<ISystemService, SystemService>();

        return builder;
    }
}
