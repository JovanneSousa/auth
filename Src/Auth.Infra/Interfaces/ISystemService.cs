using Auth.Domain.DTOs;
using Auth.Domain.Entities;
using Auth.Infra.Identity;

namespace Auth.Infra.Interfaces
{
    public interface ISystemService
    {
        Task<bool> AdicionaSistemaAsync(SystemEntity sistema);
        Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync();
        Task<IEnumerable<SystemViewModel>> ObterSistemasPorRoleNameAsync(IList<string> rolesName);
    }
}
