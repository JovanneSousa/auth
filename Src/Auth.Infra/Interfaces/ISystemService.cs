using Auth.Domain.Entities;

namespace Auth.Infra.Interfaces
{
    public interface ISystemService
    {
        Task<bool> AdicionaSistemaAsync(SystemEntity sistema);
        Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync();
    }
}
