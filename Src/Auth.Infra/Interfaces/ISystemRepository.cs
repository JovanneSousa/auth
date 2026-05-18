using Auth.Domain.Entities;
using Auth.Infra.Identity;

namespace Auth.Infra.Interfaces
{
    public interface ISystemRepository
    {
        Task<bool> AdicionarAsync(SystemEntity system);
        Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync();
        Task<IEnumerable<SystemEntity>> ObterSistemasPorRolesAsync(IEnumerable<string> role);
        Task<SystemEntity?> ObterSistemaPorNome(string nome);
        Task<bool> AdicionaRole(ApplicationRole role);
    }
}
