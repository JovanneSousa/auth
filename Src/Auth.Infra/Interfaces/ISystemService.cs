using Auth.Domain.ViewModel;
using Auth.Domain.Entities;
namespace Auth.Infra.Interfaces
{
    public interface ISystemService
    {
        Task<bool> AdicionaSistemaAsync(SystemViewModel sistema);
        Task<List<SystemViewModel>> ObterTodosSistemasAsync();
        Task<bool> AdicionaRole(ApplicationRoleViewModel roleVm);
        // --------------- METODO ANTIGO, PARA APRESENTAÇÃO NA FACULDADE ------------------------
        //Task<IEnumerable<SystemViewModel>> ObterSistemasPorRoleNameAsync(IList<string> rolesName);
    }
}
