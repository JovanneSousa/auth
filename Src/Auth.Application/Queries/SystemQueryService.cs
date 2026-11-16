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
            LEFT JOIN ""AspNetRoleClaims"" c ON c.""RoleId"" = r.""Id"" AND c.""ClaimType"" = 'permission'
        ";

        private static string ObterSqlUsuariosPorSistema() => @"
            SELECT
                u.""Id""        AS UserId,
                u.""Nome"",
                u.""Email"",
                r.""Id""        AS RoleId,
                r.""Name"",
                s.""Id""        AS SystemId,
                s.""Name"",
                s.""Url""
            FROM ""AspNetUsers"" u
            INNER JOIN ""AspNetUserRoles"" ur ON u.""Id"" = ur.""UserId""
            INNER JOIN ""AspNetRoles""     r  ON r.""Id"" = ur.""RoleId""
            INNER JOIN ""SystemEntity""    s  ON s.""Id"" = r.""SystemId""
            WHERE s.""Id"" = @SystemId
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
                var lookup = new Dictionary<string, SystemViewModel>(StringComparer.Ordinal);
                var roleLookup = new Dictionary<string, ApplicationRoleViewModel>(StringComparer.Ordinal);

                await connection.QueryAsync<SystemDapperDTO, ApplicationRoleDapperDTO, string, SystemViewModel>(
                    ObterSqlSistemasComPermissao(),
                    (system, roleDto, claim) => MontaSistema(system, roleDto, claim, lookup, roleLookup),
                    splitOn: "RoleId,ClaimValue"
                );

                return lookup.Values.ToList();
            });

            return result ?? new();
        }

        public async Task<List<AuthUserViewModel>> ObterUsuariosPorSistema(string sistemaId)
        {
            var result = await ExecuteQueryAsync(async connection =>
            {
                var lookup = new Dictionary<string, AuthUserViewModel>(StringComparer.Ordinal);

                await connection.QueryAsync<AuthUserDapperDTO, ApplicationRoleDapperDTO, SystemDapperDTO, AuthUserViewModel>(
                    ObterSqlUsuariosPorSistema(),
                    (usuario, role, sistema) =>
                    {
                        if (!lookup.TryGetValue(usuario.UserId, out var user))
                        {
                            user = usuario.ToViewModel();
                            lookup.Add(user.Id, user);
                        }

                        if (sistema != null && !string.IsNullOrEmpty(sistema.SystemId))
                        {
                            var sysVm = user.Systems.FirstOrDefault(s => s.Id == sistema.SystemId);
                            if (sysVm is null)
                            {
                                user.Systems.Add(sistema.ToViewModel(role));
                            }
                            else if (role != null && role.EhValido() && !sysVm.Permissoes.Any(p => p.Id == role.RoleId))
                            {
                                sysVm.Permissoes.Add(role.ToViewModel());
                            }
                        }

                        return user;
                    },
                    new { SystemId = sistemaId },
                    splitOn: "RoleId, SystemId");

                return lookup.Values.ToList();
            });

            return result ?? new();
        }

        private static SystemViewModel MontaSistema(
            SystemDapperDTO system,
            ApplicationRoleDapperDTO roleDto, 
            string claim,
            Dictionary<string, SystemViewModel> lookup,
            Dictionary<string, ApplicationRoleViewModel> roleLookup
            )
        {
            if (!lookup.TryGetValue(system.SystemId, out var sys))
            {
                sys = system.ToViewModel();
                lookup.Add(sys.Id, sys);
            }

            if (roleDto.EhValido())
            {
                if (!roleLookup.TryGetValue(roleDto.RoleId, out var role))
                {
                    role = roleDto.ToViewModel();
                    roleLookup.Add(role.Id, role);
                    sys.Permissoes.Add(role);
                }

                if (!string.IsNullOrEmpty(claim))
                    role.Claims.Add(new ApplicationClaimViewModel(role.Id, claim));
            }

            return sys;
        }
    }
}
