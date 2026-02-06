using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace auth.Domain.Interfaces;

public interface IUsuarioRepository
{
    Task<IdentityUser?> ObterUsuarioPorEmailAsync(string email);
    Task<IdentityResult> AdicionarUsuarioAsync(IdentityUser user, string password);
    Task<IList<Claim>> ObterClaimsAsync(IdentityUser user);
    Task<IdentityResult> SalvaClaimsAsync(IdentityUser user, IList<Claim> claims);
    Task<IList<string>> ObterRolesAsync(IdentityUser user);
    Task<string> GeraTokenReset(IdentityUser user);
    Task<bool> isEmailConfirmed(IdentityUser user);
    Task<IdentityResult> ResetSenha(IdentityUser user, string token, string password);
    Task<SignInResult> LogarComSenha(string user, string password);
    Task LogarAsync(IdentityUser user);
}
