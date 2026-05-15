using Auth.Domain.Entities;
using Auth.Domain.Exceptions;
using Auth.Infra.Interfaces;

namespace Auth.Application.Services
{
    public abstract class BaseService
    {
        protected readonly INotificador _notificador;

        protected BaseService(INotificador notificador)
        {
            _notificador = notificador;
        }

        protected async Task<T?> ExecuteAsync<T>(Func<Task<T>> action)
        {
            try
            {
                return await action();
            }
            catch (DatabaseException ex)
            {
                return _notificador.Handle<T>($"Erro no banco: {ex.Message}");
            }
        }

        protected async Task ExecuteAsync(Func<Task> action)
        {
            await ExecuteAsync(async () =>
            {
                await action();
                return true;
            });
        }

        protected T? AdicionaErroProcessamento<T>(string erro)
            => _notificador.Handle<T>(erro);
    }
}
