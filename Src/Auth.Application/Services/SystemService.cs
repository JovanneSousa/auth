using Auth.Domain.DTOs;
using Auth.Domain.Entities;
using Auth.Infra.Interfaces;
using System.Data;

namespace Auth.Application.Services
{
    public class SystemService : BaseService, ISystemService
    {
        private readonly ISystemRepository _systemRepository;
        private readonly IAuthRepository _authRepository;
        public SystemService(
            INotificador notificador,
            ISystemRepository systemRepository,
            IAuthRepository authRepository)
            : base(notificador)
        {
            _systemRepository = systemRepository;
            _authRepository = authRepository;
        }

        public async Task<bool> AdicionaSistemaAsync(SystemEntity sistema)
        {
            return await ExecuteAsync(
                async () => await _systemRepository.AdicionarAsync(sistema));
        }

        public async Task<SystemViewModel[]> ObterTodosSistemasAsync()
        {
            var sistemasModel = 
                await ExecuteAsync(async () => await _systemRepository.ObterTodosSistemasAsync());

            var sistemasViewModel = await Task.WhenAll(sistemasModel.Select(async system =>
            {
                var roles = await ExecuteAsync(async () =>
                    await _authRepository.ObterRolesPorSistemIdAsync(system.Id));

                var permissoes = await Task.WhenAll(roles.Select(async role =>
                {
                    var claims = await ExecuteAsync(async () =>
                        await _authRepository.ObterClaimsRoleAsync(role));

                    return new ApplicationRoleViewModel
                    {
                        Id = role.Id,
                        Name = role.Name,
                        Claims = claims.Select(c => c.Value).ToList()
                    };
                }));

                return new SystemViewModel
                {
                    Id = system.Id,
                    Name = system.Name,
                    Url = system.Url,
                    Permissoes = permissoes.ToList()
                };
            }));

            return sistemasViewModel;
        }

        public async Task<IEnumerable<SystemViewModel>> ObterSistemasPorRoleNameAsync(IList<string> rolesName)
        {
            var roles = await ExecuteAsync(async () => 
                await _authRepository.ObterSystemIdDasRolesPorUsuarioAsync(rolesName));

            var systemIds = roles
                .Select(r => r.SystemId)
                .Distinct()
                .ToList();

            var systems = await ExecuteAsync(async () => 
                await _systemRepository.ObterSistemasPorRolesAsync(systemIds));

            var rolesPorSistema = roles
                .GroupBy(r => r.SystemId)
                .ToDictionary(g => g.Key, g => g.ToList());

            var result = systems.Select(system => 
            {
                rolesPorSistema.TryGetValue(system.Id, out var rolesDoSistema);
                return new SystemViewModel
                {
                    Id = system.Id,
                    Name = system.Name,
                    Url = system.Url,
                    Permissoes = rolesDoSistema?
                        .Select(r => new ApplicationRoleViewModel
                        {
                            Id = r.Id,
                            Name = r.Name
                        }).ToList() ?? new List<ApplicationRoleViewModel>()
                };
            });

            return result;
        }
    }
}
