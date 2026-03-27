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
        public AuthQueryService(
            ApplicationDbContext context, 
            INotificador notificador) : base(context, notificador)
        {
        }
        public async Task<AuthUserViewModel> ObterUsuarioPorId(string id)
        {
            var sql = @"
                select 
	                u.""Id"" AS UserId,
	                u.""Nome"", 
	                u.""Email"", 
	                r.""Id"" AS RoleId,
	                r.""Name"", 
	                r.""SystemId"", 
	                s.""Id"" AS SystemId,
	                s.""Name"",
	                s.""Url""
                from ""AspNetUsers"" u
                left join ""AspNetUserRoles"" ur on u.""Id"" = ur.""UserId""
                left join ""AspNetRoles"" r on r.""Id"" = ur.""RoleId""
                left join ""SystemEntity"" s on s.""Id"" = r.""SystemId""

                where u.""Id"" = @UserId
            ";

            return await ExecuteQueryAsync(async connection =>
            {
                var lookup = new Dictionary<string, AuthUserViewModel>();

                await connection.QueryAsync<AuthUserDapperDTO, SystemDapperDTO, AuthUserViewModel>(
                    sql,
                    (usuario, sistema) => 
                    {
                        if(!lookup.TryGetValue(usuario.UserId, out var user))
                        {
                            user = new AuthUserViewModel
                            {
                                Id = usuario.UserId,
                                Nome = usuario.Nome,
                                Email = usuario.Email
                            };
                            user.Systems = new List<SystemViewModel>();
                            lookup.Add(user.Id, user);
                        }

                        if (sistema != null && !string.IsNullOrEmpty(sistema.SystemId))
                        {
                            user.Systems.Add(new SystemViewModel { Id = sistema.SystemId, Name = sistema.Name, Url = sistema.Url});
                        }

                        return user;
                    },
                    new { UserId = id },
                    splitOn: "RoleId, SystemId");

                return lookup.Values.FirstOrDefault();
            });
        }
    }
}
