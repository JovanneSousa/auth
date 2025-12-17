using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace auth.Domain.Interfaces;

public interface IUsuarioRepository
{
    public Task<IdentityUser?> ObterUsuarioPorEmailAsync(string email);
    public Task<IdentityResult> AdicionarUsuarioAsync(IdentityUser user, string password);
    public Task<IList<Claim>> ObterClaimsAsync(IdentityUser user);
    public Task<IdentityResult> SalvaClaimsAsync(IdentityUser user, IList<Claim> claims);
    public Task<IList<string>> ObterRolesAsync(IdentityUser user);
}
