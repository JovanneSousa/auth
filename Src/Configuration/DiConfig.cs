using auth.Domain.Interfaces;
using auth.Domain.Repositories;
using auth.Domain.Services;
using auth.Infra.MessageBus;
using auth.Infra.Notifications;
using Infra.MessageBus;
using MessageBus;
namespace auth.Configuration;

public static class DiConfig
{
    public static async Task<WebApplicationBuilder> AddDiConfig(this WebApplicationBuilder builder)
    {
        var rabbit = builder.Configuration.GetSection("rabbit").Get<RabbitSettings>();
        if (string.IsNullOrEmpty(rabbit?.Url) || string.IsNullOrEmpty(rabbit.Exchange))
            throw new InvalidOperationException("rabbit não configurado");
        //var rabbitProducer = await RabbitMqProducer.CreateAsync(rabbit.Url, rabbit.Exchange);

        builder.Services.AddScoped<INotificador, Notificador>();
        builder.Services.AddScoped<IUsuarioRepository, UsuarioRepository>();
        builder.Services.AddScoped<IUsuarioService, UsuarioService>();
        builder.Services.AddMessageBus(rabbit.Url);
        return builder;
    }
}
