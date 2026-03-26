using Auth.Application.Data;
using Auth.Domain.Entities;
using Auth.Infra.Interfaces;
using Microsoft.EntityFrameworkCore;
using System.Data;

namespace Auth.Application.Queries
{
    public abstract class BaseQueryService
    {
        private readonly ApplicationDbContext _context;
        private readonly INotificador _notificador;
        public BaseQueryService(
            ApplicationDbContext context, 
            INotificador notificador)
        {
            _context = context;
            _notificador = notificador;
        }

        private async Task<IDbConnection> GetConnection()
        {
            var connection = _context.Database.GetDbConnection();

            if (connection.State != ConnectionState.Open)
                await connection.OpenAsync();

            return connection;
        }

        protected async Task<T> ExecuteQueryAsync<T>(Func<IDbConnection, Task<T>> action)
        {
            try
            {
                var connection = await GetConnection();
                return await action(connection);
            }
            catch (Exception ex)
            {
                _notificador.Handle(new Notificacao($"Erro no PostgreSQL, {ex.Message}"));
                return default;
            }
        }
    }
}
