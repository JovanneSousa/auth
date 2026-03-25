using Microsoft.AspNetCore.Identity;

namespace Auth.Infra.Identity
{
    public class ApplicationUser : IdentityUser
    {
        public string Nome { get; set; }
    }
}
