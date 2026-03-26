using Auth.Application.Data;
using Auth.Application.DTOs;
using Auth.Application.Queries.Interfaces;
using Auth.Domain.ViewModel;
using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Dapper;

namespace Auth.Application.Queries
{
    public class SystemQueryService : BaseQueryService, ISystemQueryService
    {
        public SystemQueryService(
            ApplicationDbContext context, 
            INotificador notificador) 
            : base(context, notificador)
        {
        }

        public async Task<List<SystemViewModel>> ObterSistemasComPermissoes()
        {
            var sql = @"
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

            return await ExecuteQueryAsync(async connection =>
            {
                var lookup = new Dictionary<string, SystemViewModel>();

                var result = await connection.QueryAsync<SystemDapperDTO, ApplicationRoleDapperDTO, string, SystemViewModel>(
                    sql,
                    (system, roleDto, claim) =>
                    {
                        if (!lookup.TryGetValue(system.SystemId, out var sys))
                        {
                            sys = new SystemViewModel
                            {
                                Id = system.SystemId,
                                Name = system.Name,
                                Url = system.Url
                            };
                            sys.Permissoes = new List<ApplicationRoleViewModel>();
                            lookup.Add(sys.Id, sys);
                        }

                        if (roleDto != null && !string.IsNullOrEmpty(roleDto.RoleId))
                        {
                            var role = sys.Permissoes
                                .FirstOrDefault(r => r.Id == roleDto.RoleId);

                            if (role == null)
                            {
                                role = new ApplicationRoleViewModel
                                {
                                    Id = roleDto.RoleId,
                                    Name = roleDto.Name,
                                    Claims = new List<string>()
                                };
                                sys.Permissoes.Add(role);
                            }

                            if (claim != null && !string.IsNullOrEmpty(claim))
                                role.Claims.Add(claim);
                        }

                        return sys;
                    },
                    splitOn: "RoleId,ClaimValue"
                );

                return lookup.Values.ToList();
            });
        }
    }
}
