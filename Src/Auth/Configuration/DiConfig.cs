
using auth.Domain.Services;
using auth.Infra.Notifications;
using auth.Domain.Repositories;
using auth.Domain.Interfaces;

namespace auth.Configuration;

public static class DiConfig
{
    public static async Task<WebApplicationBuilder> AddDiConfig(this WebApplicationBuilder builder)
    {
        builder.Services.AddScoped<INotificador, Notificador>();
        builder.Services.AddScoped<IUsuarioRepository, UsuarioRepository>();
        builder.Services.AddScoped<IUsuarioService, UsuarioService>();

        return builder;
    }
}
