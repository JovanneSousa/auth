using Auth.Application.DTOs;
using Auth.Application.Extensions;
using Auth.Application.Queries.Interfaces;
using Auth.Domain.ViewModel;
using Auth.Infra.Data;
using Auth.Infra.Interfaces;
using System.Security.Claims;
using Dapper;

namespace Auth.Application.Queries
{
    public class SystemQueryService : BaseQueryService, ISystemQueryService
    {
        private static string ObterSqlSistemasComPermissao() => @"
            SELECT 
                s.""Id"" AS SystemId,
                s.""Name"",
                s.""Url"",
                r.""Id"" AS RoleId,
                r.""Name"" AS Name,
                c.""ClaimValue""
            FROM ""SystemEntity"" s
            LEFT JOIN ""AspNetRoles"" r ON r.""SystemId"" = s.""Id""
            LEFT JOIN ""AspNetRoleClaims"" c ON c.""RoleId"" = r.""Id""
        ";
        public SystemQueryService(
            ApplicationDbContext context, 
            INotificador notificador) 
            : base(context, notificador)
        {
        }

        public async Task<List<SystemViewModel>> ObterSistemasComPermissoes()
        {
            var result = await ExecuteQueryAsync(async connection =>
            {
                var lookup = new Dictionary<string, SystemViewModel>();

                await connection.QueryAsync<SystemDapperDTO, ApplicationRoleDapperDTO, string, SystemViewModel>(
                    ObterSqlSistemasComPermissao(),
                    (system, roleDto, claim) => MontaSistema(system, roleDto, claim, lookup),
                    splitOn: "RoleId,ClaimValue"
                );

                return lookup.Values.ToList();
            });

            return result ?? new();
        }

        private SystemViewModel MontaSistema(
            SystemDapperDTO system,
            ApplicationRoleDapperDTO roleDto, 
            string claim,
            Dictionary<string, SystemViewModel> lookup
            )
        {
            if (!lookup.TryGetValue(system.SystemId, out var sys))
            {
                sys = system.ToViewModel();
                lookup.Add(sys.Id, sys);
            }

            if (roleDto.EhValido())
            {
                var role = sys.Permissoes
                    .FirstOrDefault(r => r.Id == roleDto.RoleId);

                if (role is null)
                {
                    role = roleDto.ToViewModel();
                    sys.Permissoes.Add(role);
                }

                if (!string.IsNullOrEmpty(claim))
                    role.Claims.Add(new ApplicationClaimViewModel(role.Id, claim));
            }

            return sys;
        }
    }
}
