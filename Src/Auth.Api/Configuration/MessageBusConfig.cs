using Configuration;

namespace Auth.Api.Configuration
{
    public static class MessageBusConfig
    {
        public static async Task<WebApplicationBuilder> AddMessageBus(this WebApplicationBuilder builder)
        {
            await builder.Services
                .AddRabbitConfiguration(builder.Configuration);

            return builder;
        }
    }
}
