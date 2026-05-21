using Auth.Domain.ViewModel;
using System.Security.Claims;

namespace Auth.Application.Extensions
{
    public static class ApplicationClaimViewModelExtensions
    {
        public static Claim ToClaim(this ApplicationClaimViewModel claim)
            => new Claim("permission", claim.ClaimValue.ToUpper());
    }
}
