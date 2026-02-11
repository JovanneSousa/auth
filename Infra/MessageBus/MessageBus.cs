using auth.Infra.MessageBus;
using RabbitMQ.Client;
using System.Text;
using System.Text.Json;

namespace Infra.MessageBus
{
    public sealed class MessageBus : IMessageBus, IDisposable
    {
        private readonly IConnection _connection;
        private readonly IChannel _channel;
        private readonly string _exchangeName;
        private readonly JsonSerializerOptions _jsonOptions;

        public MessageBus(IConnection connection, IChannel channel, string exchangeName)
        {
            _exchangeName = exchangeName;
            _connection = connection;
            _channel = channel;

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        public static async Task<MessageBus> CreateAsync(
            string amqpUri, 
            string exchangeName, 
            CancellationToken ct = default
            ) 
        {
            var factory = new ConnectionFactory 
            { 
                Uri = new Uri(amqpUri),
                AutomaticRecoveryEnabled = true,
                TopologyRecoveryEnabled = true
            };

            var connection = await factory.CreateConnectionAsync(ct);
            var channel = await connection.CreateChannelAsync();

            await channel.ExchangeDeclareAsync(
                            exchange: exchangeName,
                            type: ExchangeType.Topic,
                            durable: true,
                            autoDelete: false,
                            arguments: null,
                            cancellationToken: ct
                        );

            return new MessageBus(connection, channel, exchangeName);
        }

        public async Task PublishAsync<T>(T message, string routingKey) where T : class
        {
            var json = JsonSerializer.Serialize(message, _jsonOptions);
            var body = Encoding.UTF8.GetBytes(json);

            await _channel.BasicPublishAsync(
                exchange: _exchangeName,
                routingKey: routingKey,
                mandatory: false,
                body: body,
                basicProperties: geraPropriedades()
            );
        }

        private BasicProperties geraPropriedades() =>
            new BasicProperties
            {
                ContentType = "application/json",
                ContentEncoding = "utf-8",
                DeliveryMode = DeliveryModes.Persistent
            };

        public void Dispose()
        {
            if (_channel != null)
                _channel.Dispose();
            if(_connection != null )
                _connection.Dispose();
        }
    }
}
