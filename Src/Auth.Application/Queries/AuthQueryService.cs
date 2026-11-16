using Auth.Application.DTOs;
using Auth.Application.Extensions;
using Auth.Application.Queries.Interfaces;
using Auth.Domain.ViewModel;
using Auth.Infra.Data;
using Auth.Infra.Interfaces;
using Dapper;

namespace Auth.Application.Queries
{
    public class AuthQueryService : BaseQueryService, IAuthQueryService
    {
        private static string ObterSqlUsuarioPorId() => @"
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
                    LEFT JOIN ""AspNetUserRoles"" ur ON u.""Id"" = ur.""UserId""
                    LEFT JOIN ""AspNetRoles""     r  ON r.""Id"" = ur.""RoleId""
                    LEFT JOIN ""SystemEntity""    s  ON s.""Id"" = r.""SystemId""
                    WHERE u.""Id"" = @UserId";

        private static string ObterSqlUsuarios() => @"
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
                    LEFT JOIN ""AspNetUserRoles"" ur ON u.""Id"" = ur.""UserId""
                    LEFT JOIN ""AspNetRoles""     r  ON r.""Id"" = ur.""RoleId""
                    LEFT JOIN ""SystemEntity""    s  ON s.""Id"" = r.""SystemId""";

        public AuthQueryService(
            ApplicationDbContext context,
            INotificador notificador) : base(context, notificador)
        {
        }

        public async Task<AuthUserViewModel?> ObterUsuarioPorId(string id)
        {
            return await ExecuteQueryAsync(async connection =>
            {
                var lookup = new Dictionary<string, AuthUserViewModel>(StringComparer.Ordinal);

                await connection.QueryAsync<AuthUserDapperDTO, ApplicationRoleDapperDTO, SystemDapperDTO, AuthUserViewModel>(
                    ObterSqlUsuarioPorId(),
                    (usuario, role, sistema) => MapearUsuarioSistemaRole(usuario, role, sistema, lookup),
                    new { UserId = id },
                    splitOn: "RoleId, SystemId");

                return lookup.Values.FirstOrDefault();
            });
        }

        public async Task<List<AuthUserViewModel>> ObterUsuariosComSistemas()
        {
            var result = await ExecuteQueryAsync(async connection =>
            {
                var lookup = new Dictionary<string, AuthUserViewModel>(StringComparer.Ordinal);

                await connection.QueryAsync<AuthUserDapperDTO, ApplicationRoleDapperDTO, SystemDapperDTO, AuthUserViewModel>(
                    ObterSqlUsuarios(),
                    (usuario, role, sistema) => MapearUsuarioSistemaRole(usuario, role, sistema, lookup),
                    splitOn: "RoleId, SystemId");

                return lookup.Values.ToList();
            });

            return result ?? new();
        }

        private static AuthUserViewModel MapearUsuarioSistemaRole(
            AuthUserDapperDTO usuario,
            ApplicationRoleDapperDTO role,
            SystemDapperDTO sistema,
            Dictionary<string, AuthUserViewModel> lookup)
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
        }
    }
}
