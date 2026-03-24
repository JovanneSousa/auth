using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Auth.Infra.Identity;

namespace Auth.Infra.Interfaces
{
    public interface IAuthRepository
    {
        Task<IdentityUser?> ObterUsuarioPorEmailAsync(string email);
        Task<IEnumerable<IdentityUser>> ObterTodosAuthUserAsync();
        Task<IdentityResult> AdicionarUsuarioAsync(IdentityUser user, string password);
        Task<IdentityResult> DeleteAsync(IdentityUser usuario);

        Task<IList<Claim>> ObterClaimsAsync(IdentityUser user);
        Task<IdentityResult> SalvaClaimsAsync(IdentityUser user, IList<Claim> claims);

        Task<IdentityResult> SalvaRoleAsync(IdentityUser user, string role);
        Task<IList<string>> ObterRolesAsync(IdentityUser user);
        Task<ApplicationRole> ObterRolePorNomeAsync(string nome);
        Task<IList<Claim>> ObterClaimsRoleAsync(ApplicationRole role);

        Task<bool> isEmailConfirmed(IdentityUser user);

        Task<string> GeraTokenReset(IdentityUser user);
        Task<IdentityResult> ResetarSenha(IdentityUser user, string token, string newPassword);
    }
}