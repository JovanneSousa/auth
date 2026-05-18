using Auth.Application.Repositories;
using Auth.Domain.Entities;
using Auth.Infra.Data;
using Auth.Infra.Identity;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infra.Repositories
{
    public class SystemRepository : BaseRepository, ISystemRepository
    {
        private readonly ApplicationDbContext _context;

        public SystemRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<bool> AdicionarAsync(SystemEntity system)
            => await ExecuteAsync(async () =>
                {
                    await _context.SystemEntity.AddAsync(system);
                    await _context.SaveChangesAsync();
                    return true;
                });

        public async Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync()
            => await ExecuteAsync(async () => await _context.SystemEntity.ToListAsync());

        public async Task<IEnumerable<SystemEntity>> ObterSistemasPorRolesAsync(IEnumerable<string> systemIds)
        {
            return await ExecuteAsync(async () => 
                    await _context.SystemEntity
                        .Where(s => systemIds.Contains(s.Id))
                        .ToListAsync());
        }

        public async Task<SystemEntity?> ObterSistemaPorNome(string nome)
        {
            return await ExecuteAsync(
                async () => await _context.SystemEntity.FirstOrDefaultAsync(s => s.Name == nome)
                );
        }

        public async Task<bool> AdicionaRole(ApplicationRole role)
        {
            return await ExecuteAsync(
                async () =>
                {
                    await _context.AddAsync(role);
                    await _context.SaveChangesAsync();
                    return true;
                });
        }
    }
}
