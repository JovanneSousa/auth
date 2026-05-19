using Auth.Application.Queries.Interfaces;
using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Auth.Application.Extensions;

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

        // Sistemas
        public async Task<bool> AdicionaSistemaAsync(SystemViewModel sistema)
        {
            var sys = sistema.ToSystem();
            var errors = sys.Validate();

            if(errors.Any())
                return RetornaSerieErrosProcessamento<bool>(errors);

            var result = await ExecuteAsync(
                async () => await _systemRepository.AdicionarAsync(sys));

            if (!result)
                return RetornaErroProcessamento<bool>("Falha ao adicionar o sistema!");
            return true;
        }

        public async Task<List<SystemViewModel>> ObterTodosSistemasAsync() =>
            await _systemQuery.ObterSistemasComPermissoes();

        public async Task AtualizaSistema(SystemViewModel sistema)
        {
            var original = await _systemRepository.ObterSistemaPorNome(sistema.Name);
        }

        public Task<bool> RemoveSistemaAsync(string sistemaId)
        {
            throw new NotImplementedException();
        }


        // Roles
        public async Task<bool> AdicionaRole(ApplicationRoleViewModel roleVm)
        {
            var result = await ExecuteAsync(async () => await _systemRepository.AdicionaRole(roleVm.toRole()));
            if (!result)
                return RetornaErroProcessamento<bool>("Falha ao adicionar o perfil!");
            return true;
        }

        public Task<bool> RemoverRole(string roleId)
        {
            throw new NotImplementedException();
        }

        // Claims
        public Task<bool> AdicionaClaim(string roleId, string claimValue)
        {
            throw new NotImplementedException();
        }

        public Task<bool> RemoveClaim(string claimId)
        {
            throw new NotImplementedException();
        }
    }
}
