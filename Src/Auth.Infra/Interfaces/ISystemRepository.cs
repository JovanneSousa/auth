using Auth.Domain.Entities;
using Auth.Domain.ViewModel;
using Auth.Infra.Identity;

namespace Auth.Infra.Interfaces
{
    public interface ISystemRepository
    {
        Task<bool> AdicionarAsync(SystemEntity system);
        Task<bool> AtualizarAsync(SystemEntity system);
        Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync();
        Task<IEnumerable<SystemEntity>> ObterSistemasPorRolesAsync(IEnumerable<string> role);
        Task<SystemEntity?> ObterSistemaPorNome(string nome);
        Task<SystemEntity?> ObterSistemaPorId(string id);
        Task<bool> AdicionaRole(ApplicationRole role);
    }
}
