using Auth.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Auth.Infra.Identity
{
    public class ApplicationRole : IdentityRole
    {
        public required string SystemId { get; set; }
        public required SystemEntity System { get; set; }
    }
}
