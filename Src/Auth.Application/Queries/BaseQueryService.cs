using Auth.Application.Services;
using Auth.Infra.Data;
using Auth.Infra.Interfaces;
using Microsoft.EntityFrameworkCore;
using System.Data;

namespace Auth.Application.Queries
{
    public abstract class BaseQueryService : BaseService
    {
        private readonly ApplicationDbContext _context;
        public BaseQueryService(
            ApplicationDbContext context, 
            INotificador notificador) : base(notificador)
        {
            _context = context;
        }

        private async Task<IDbConnection> GetConnection()
        {
            var connection = _context.Database.GetDbConnection();

            if (connection.State != ConnectionState.Open)
                await connection.OpenAsync();

            return connection;
        }

        protected async Task<T?> ExecuteQueryAsync<T>(Func<IDbConnection, Task<T>> action)
        {
            try
            {
                var connection = await GetConnection();
                return await action(connection);
            }
            catch (Exception ex)
            {
                return AdicionaErroProcessamento<T>($"Erro no PostgreSQL, {ex.Message}");
            }
        }
    }
}
