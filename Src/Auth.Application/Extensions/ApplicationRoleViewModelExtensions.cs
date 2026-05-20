using Auth.Domain.ViewModel;
using Auth.Infra.Identity;

namespace Auth.Application.Extensions
{
    public static class ApplicationRoleViewModelExtensions
    {
        public static ApplicationRole toRole(this ApplicationRoleViewModel role)
        {
            return new ApplicationRole 
            { 
                Id = role.Id,
                Name = role.Name,
                NormalizedName = role.Name.ToUpper(),
                SystemId = role.SystemId,
            };
        }
    }
}
