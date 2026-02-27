using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Auth.Application.Repositories;

public interface IAuthRepository
{
    Task<IdentityUser?> ObterUsuarioPorEmailAsync(string email);
    Task<IEnumerable<IdentityUser>> ObterTodosAuthUserAsync();
    Task<IdentityResult> AdicionarUsuarioAsync(IdentityUser user, string password);
    Task<IList<Claim>> ObterClaimsAsync(IdentityUser user);
    Task<IdentityResult> SalvaClaimsAsync(IdentityUser user, IList<Claim> claims);
    Task<IList<string>> ObterRolesAsync(IdentityUser user);
    Task<string> GeraTokenReset(IdentityUser user);
    Task<bool> isEmailConfirmed(IdentityUser user);
    Task<IdentityResult> ResetarSenha(IdentityUser user, string token, string newPassword);
    Task<IdentityResult> DeleteAsync(IdentityUser usuario);
}
