using System.Security.Claims;

using Auth.Application.Queries.Interfaces;
using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Auth.Application.Extensions;
using Auth.Domain.Entities;
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
        public async Task<List<SystemViewModel>> ObterTodosSistemasOldAsync()
        {
            var sistemasModel =
                await ExecuteAsync(async () => await _systemRepository.ObterTodosSistemasAsync());
            if (sistemasModel is null)
                sistemasModel = new List<SystemEntity>();

            List<SystemViewModel> system = new();
            foreach(var sys in sistemasModel)
            {
                var roles = await ExecuteAsync(async () =>
                    await _authRepository.ObterRolesPorSistemIdAsync(sys.Id));

                var permissoes = new List<ApplicationRoleViewModel>();

                foreach (var role in roles ?? Enumerable.Empty<ApplicationRole>())
                {
                    var claimsEntity = await ExecuteAsync(async () =>
                        await _authRepository.ObterClaimsRoleAsync(role));

                    var claims = (claimsEntity ?? Enumerable.Empty<Claim>())
                        .Select(c => new ApplicationClaimViewModel(role.Id, c.Value))
                        .ToList();

                    permissoes.Add(new ApplicationRoleViewModel
                    {
                        SystemId = sys.Id,
                        Id = role.Id,
                        Name = role.Name ?? "",
                        Claims = claims
                    });
                }

                system.Add(new SystemViewModel
                {
                    Id = sys.Id,
                    Name = sys.Name,
                    Url = sys.Url,
                    Permissoes = permissoes.ToList()
                });
            };

            return system;
        }

        public async Task<bool> AtualizaSistemaAsync(SystemViewModel sistema)
        {
            if (string.IsNullOrEmpty(sistema.Url) || string.IsNullOrEmpty(sistema.Name))
                return RetornaErroProcessamento<bool>("O nome e url são obrigatórios!");

            var original = await ExecuteAsync(async () => await _systemRepository.ObterSistemaPorId(sistema.Id));
            if (original is null)
                return RetornaErroProcessamento<bool>("Sistema não encontrado!");

            original.Url = sistema.Url;
            original.Name = sistema.Name;

            var result = await ExecuteAsync(async () => await _systemRepository.AtualizarAsync(original));
            if (!result)
                RetornaErroProcessamento<bool>("Falha ao atualizar sistema!");

            return true;
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

        public async Task<bool> RemoverRole(string roleId)
        {
            var role = await ExecuteAsync(async () => await _authRepository.ObterRolePorId(roleId));
            if (role is null)
                return RetornaErroProcessamento<bool>("Role não encontrada!");

            var claims = await ExecuteAsync(async () => await _authRepository.ObterClaimsRoleAsync(role));
            if (claims is not null && claims.Any())
                return RetornaErroProcessamento<bool>("Não foi possivel excluir a role, pois ela possui claims");

            var result = await ExecuteAsync(async () => await _authRepository.RemoverRoleAsync(role));
            if (result is null || !result.Succeeded)
                RetornaErroProcessamento<bool>("Falha inesperada ao excluir a role!");

            return true;
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
