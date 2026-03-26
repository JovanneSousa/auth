using Auth.Domain.ViewModel;
using Auth.Domain.Entities;
namespace Auth.Infra.Interfaces
{
    public interface ISystemService
    {
        Task<bool> AdicionaSistemaAsync(SystemEntity sistema);
        Task<List<SystemViewModel>> ObterTodosSistemasAsync();
        Task<IEnumerable<SystemViewModel>> ObterSistemasPorRoleNameAsync(IList<string> rolesName);
    }
}
