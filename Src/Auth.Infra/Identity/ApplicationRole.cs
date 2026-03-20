using Microsoft.AspNetCore.Identity;

namespace Auth.Infra.Identity
{
    public class ApplicationRole : IdentityRole
    {
        public string SystemId { get; set; }
    }
}
