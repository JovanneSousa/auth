using Auth.Domain.DTOs;
using Auth.Domain.Entities;
namespace Auth.Infra.Interfaces
{
    public interface ISystemService
    {
        Task<bool> AdicionaSistemaAsync(SystemEntity sistema);
        Task<SystemViewModel[]> ObterTodosSistemasAsync();
        Task<IEnumerable<SystemViewModel>> ObterSistemasPorRoleNameAsync(IList<string> rolesName);
    }
}
