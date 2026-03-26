using Auth.Domain.ViewModel;

namespace Auth.Application.Queries.Interfaces
{
    public interface ISystemQueryService
    {
        Task<List<SystemViewModel>> ObterSistemasComPermissoes();
    }
}
