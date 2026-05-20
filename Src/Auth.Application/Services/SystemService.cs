using System.Security.Claims;

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
        public async Task<bool> AdicionaClaim(ApplicationClaimViewModel claimVM)
        {
            var role = await ExecuteAsync(async () => await _authRepository.ObterRolePorId(claimVM.RoleId));
            if (role is null)
                return RetornaErroProcessamento<bool>("Falha ao adicionar claim, Role não encontrada");

            var claim = claimVM.ToClaim();
            var result = await ExecuteAsync(async () => await _authRepository.SalvaRoleClaim(role, claim));
            if (result is not null && !result.Succeeded)
                return RetornaErroProcessamento<bool>("Falha ao adicionar claim");

            return true;
        }

        public async Task<bool> RemoveClaim(string roleId, string claimValue)
        {
            var role = await ExecuteAsync(async () => await _authRepository.ObterRolePorId(roleId));
            if (role is null)
                return RetornaErroProcessamento<bool>("Falha ao excluir claim, Role não encontrada!");

            var result = await ExecuteAsync(
                async () => await _authRepository.ExcluirRoleClaim(role, new Claim("permission", claimValue))
                );
            if (result is not null && !result.Succeeded)
                return RetornaErroProcessamento<bool>("Falha ao excluir claim!");

            return true;
        }
    }
}
