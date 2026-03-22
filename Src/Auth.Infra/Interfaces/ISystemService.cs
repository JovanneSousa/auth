using Auth.Domain.Entities;

namespace Auth.Domain.Interfaces
{
    public interface ISystemService 
    {
        Task<bool> AdicionaSistemaAsync(SystemEntity sistema);
        Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync();
    }
}
