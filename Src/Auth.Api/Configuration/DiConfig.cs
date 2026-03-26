using Auth.Application.Queries;
using Auth.Application.Queries.Interfaces;
using Auth.Application.Services;
using Auth.Infra.Interfaces;
using Auth.Infra.Notifications;
using Auth.Infra.Repositories;

namespace Auth.Api.Configuration;

public static class DiConfig
{
    public static async Task<WebApplicationBuilder> AddDiConfig(this WebApplicationBuilder builder)
    {
        // Infra
        builder.Services.AddScoped<INotificador, Notificador>();

        // Repositories
        builder.Services.AddScoped<IAuthRepository, AuthRepository>();
        builder.Services.AddScoped<ISystemRepository, SystemRepository>();

        // Services
        builder.Services.AddScoped<IAuthService, AuthService>();
        builder.Services.AddScoped<ISystemService, SystemService>();

        // Querys
        builder.Services.AddScoped<ISystemQueryService, SystemQueryService>();
        builder.Services.AddScoped<IAuthQueryService, AuthQueryService>();

        return builder;
    }
}
