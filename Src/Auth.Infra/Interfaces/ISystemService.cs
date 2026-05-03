using Auth.Domain.ViewModel;
using Auth.Domain.Entities;
namespace Auth.Infra.Interfaces
{
    public interface ISystemService
    {
        Task<bool> AdicionaSistemaAsync(SystemEntity sistema);
        Task<List<SystemViewModel>> ObterTodosSistemasAsync();
        // --------------- METODO ANTIGO, PARA APRESENTAÇÃO NA FACULDADE ------------------------
        //Task<IEnumerable<SystemViewModel>> ObterSistemasPorRoleNameAsync(IList<string> rolesName);
    }
}
