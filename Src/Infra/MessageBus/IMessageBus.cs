namespace auth.Infra.MessageBus
{
    public interface IMessageBus
    {
        Task PublishAsync<T>(T message, string routingKey) where T : class;
    }
}
