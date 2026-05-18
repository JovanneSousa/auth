using Auth.Application.DTOs;
using Auth.Domain.ViewModel;

namespace Auth.Application.Extensions
{
    public static class AuthUserDapperDTOExtensions
    {
        public static AuthUserViewModel ToViewModel(this AuthUserDapperDTO usuario) =>
            new()
            {
                Email = usuario.Email,
                Id = usuario.UserId,
                Nome = usuario.Nome,
                Systems = new()
            };
    }

    public static class SystemDappterDTOExtensions
    {
        public static SystemViewModel ToViewModel(this SystemDapperDTO sistema, ApplicationRoleDapperDTO? role = default) =>
        new()
        {
            Id = sistema.SystemId,
            Name = sistema.Name,
            Url = sistema.Url,
            Permissoes = role is not null 
                ? new List<ApplicationRoleViewModel> { role.ToViewModel() } 
                : new()
        };
    }

    public static class ApplicationRoleDapperDTOExtensions
    {
        public static ApplicationRoleViewModel ToViewModel(this ApplicationRoleDapperDTO role) =>
            new()
            {
                Id = role.RoleId,
                Name = role.Name,
                SystemId = string.Empty,
                Claims = role.Claims ?? new()
            };

        public static bool EhValido(this ApplicationRoleDapperDTO role) 
            => role is not null && !string.IsNullOrEmpty(role.RoleId);
    }
}
