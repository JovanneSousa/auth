using Auth.Application.DTOs;
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
                        r.""SystemId"",
                        s.""Id""        AS SystemId,
                        s.""Name"",
                        s.""Url""
                    FROM ""AspNetUsers"" u
                    LEFT JOIN ""AspNetUserRoles"" ur ON u.""Id"" = ur.""UserId""
                    LEFT JOIN ""AspNetRoles""     r  ON r.""Id"" = ur.""RoleId""
                    LEFT JOIN ""SystemEntity""    s  ON s.""Id"" = r.""SystemId""
                    WHERE u.""Id"" = @UserId";

        public AuthQueryService(
            ApplicationDbContext context,
            INotificador notificador) : base(context, notificador)
        {
        }



        public async Task<AuthUserViewModel?> ObterUsuarioPorId(string id)
        {
            return await ExecuteQueryAsync(async connection =>
            {
                var lookup = new Dictionary<string, AuthUserViewModel>();

                await connection.QueryAsync<AuthUserDapperDTO, ApplicationRoleDapperDTO, SystemDapperDTO, AuthUserViewModel>(
                    ObterSqlUsuarioPorId(),
                    (usuario, role, sistema) =>
                    {
                        if (!lookup.TryGetValue(usuario.UserId, out var user))
                        {
                            user = CriarUsuario(usuario);
                            lookup.Add(user.Id, user);
                        }

                        if (sistema != null && !string.IsNullOrEmpty(sistema.SystemId))
                            user.Systems.Add(CriarSystemViewModel(sistema, role));

                        return user;
                    },
                    new { UserId = id },
                    splitOn: "RoleId, SystemId");

                return lookup.Values.FirstOrDefault();
            });
        }

        private SystemViewModel CriarSystemViewModel(SystemDapperDTO sistema, ApplicationRoleDapperDTO role)
            => new SystemViewModel
            {
                Id = sistema.SystemId,
                Name = sistema.Name,
                Url = sistema.Url,
                Permissoes = new List<ApplicationRoleViewModel> {
                    new()
                    {
                        Claims = role.Claims,
                        Id = role.RoleId,
                        Name = role.Name
                    }
                }
            };

        private AuthUserViewModel CriarUsuario(AuthUserDapperDTO usuario)
        {
            return new AuthUserViewModel
            {
                Email = usuario.Email,
                Id = usuario.UserId,
                Nome = usuario.Nome,
                Systems = new()
            };
        }
    }
}
