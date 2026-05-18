using Auth.Application.Queries.Interfaces;
using Auth.Domain.ViewModel;
using Auth.Domain.Entities;
using Auth.Infra.Interfaces;
using Auth.Infra.Identity;

namespace Auth.Application.Services
{
    public class SystemService : BaseService, ISystemService
    {
        private readonly ISystemRepository _systemRepository;
        private readonly IAuthRepository _authRepository;
        private readonly ISystemQueryService _systemQuery;
        public SystemService(
            INotificador notificador,
            ISystemRepository systemRepository,
            IAuthRepository authRepository,
            ISystemQueryService query)
            : base(notificador)
        {
            _systemRepository = systemRepository;
            _authRepository = authRepository;
            _systemQuery = query;
        }

        public async Task<bool> AdicionaSistemaAsync(SystemViewModel sistema)
        {
            SystemEntity sys = new() { Id = sistema.Id, Name = sistema.Name, Url = sistema.Url };
            return await ExecuteAsync(
                async () => await _systemRepository.AdicionarAsync(sys));
        }

        public async Task<List<SystemViewModel>> ObterTodosSistemasAsync() =>
            await _systemQuery.ObterSistemasComPermissoes();

        public async Task AtualizaSistema(SystemViewModel sistema)
        {
            var original = await _systemRepository.ObterSistemaPorNome(sistema.Name);
        }

        public async Task<bool> AdicionaRole(ApplicationRoleViewModel roleVm)
        {
            ApplicationRole role = new()
            {
                Id = roleVm.Id,
                Name = roleVm.Name,
                SystemId = roleVm.SystemId,
                NormalizedName = roleVm.Name.ToUpper()
            };

            return await _systemRepository.AdicionaRole(role);
        }
    }
}
