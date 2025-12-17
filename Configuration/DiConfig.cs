using auth.Extensions;
using auth.Interfaces;
using auth.Models;
using auth.Repositories;
using auth.Service;

namespace auth.Configuration;

public static class DiConfig
{
    public static WebApplicationBuilder AddDiConfig(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        builder.Services.AddScoped<INotificador, Notificador>();
        builder.Services.AddScoped<IUser, AspNetUser>();
        builder.Services.AddScoped<IUsuarioRepository, UsuarioRepository>();
        builder.Services.AddScoped<IUsuarioService, UsuarioService>();

        return builder;
    }
}
