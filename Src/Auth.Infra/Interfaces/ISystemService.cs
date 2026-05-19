using Auth.Domain.ViewModel;
namespace Auth.Infra.Interfaces
{
    public interface ISystemService
    {
        // Sistemas
        Task<bool> AdicionaSistemaAsync(SystemViewModel sistema);
        Task<bool> RemoveSistemaAsync(string sistemaId);
        Task<List<SystemViewModel>> ObterTodosSistemasAsync();

        // Roles
        Task<bool> AdicionaRole(ApplicationRoleViewModel roleVm);
        Task<bool> RemoverRole(string roleId);


        // Claims
        Task<bool> AdicionaClaim(string roleId, string claimValue);
        Task<bool> RemoveClaim(string claimId);
    }
}
