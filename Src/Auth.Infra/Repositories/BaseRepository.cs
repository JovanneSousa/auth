using Auth.Application.Data;
using Auth.Domain.Exceptions;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Auth.Application.Repositories
{
    public abstract class BaseRepository
    {
        protected readonly ApplicationDbContext _context;
        protected BaseRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        protected async Task<T> ExecuteAsync<T>(Func<Task<T>> action)
        {
            try
            {
                return await action();
            }
            catch (PostgresException ex)
            {
                throw new DatabaseException("Erro de integridade no banco.", ex);
            }
            catch (NpgsqlException ex)
            {
                throw new DatabaseException("Erro ao acessar o banco.", ex);
            }
            catch (DbUpdateException ex)
            {
                throw new DatabaseException("Erro ao persistir dados.", ex);
            }
            catch (Exception ex)
            {
                throw new DatabaseException("Erro inesperado ao acessar dados.", ex);
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

        protected async Task SaveChangesAsync()
            => await ExecuteAsync(() => _context.SaveChangesAsync());
    }
}
