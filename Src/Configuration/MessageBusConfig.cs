using NSE.Core.Utils;
using MessageBus;

namespace auth.Src.Configuration
{
    public static class MessageBusConfig
    {
        public static void AddMessageBusConfigurations(this IServiceCollection service, IConfiguration configuration)
        {
            service.AddMessageBus(configuration.GetMessageQueueConnection("MessageBus"));
        }
    }
}
