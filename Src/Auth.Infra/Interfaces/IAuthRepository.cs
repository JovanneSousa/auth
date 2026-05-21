using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Auth.Infra.Identity;

namespace Auth.Infra.Interfaces
{
    public interface IAuthRepository
    {
        // Usuarios
        Task<ApplicationUser?> ObterUsuarioPorEmailAsync(string email);
        Task<ApplicationUser?> ObterUsuarioPorIdAsync(string id);
        Task<IEnumerable<ApplicationUser>> ObterTodosAuthUserAsync();
        Task<IdentityResult> AdicionarUsuarioAsync(ApplicationUser user, string password);
        Task<IdentityResult> DeleteAsync(ApplicationUser usuario);

        //Claims
        Task<IdentityResult> SalvaRoleClaim(ApplicationRole role, Claim claim);
        Task<IdentityResult> ExcluirRoleClaim(ApplicationRole role, Claim claim);
        Task<IList<Claim>> ObterClaimsAsync(ApplicationUser user);
        Task<IList<ApplicationRole>> ObterClaimsPorRoleIdsAsync(List<string> rolesIds);

        // Roles
        Task<IdentityResult> SalvaRoleAsync(ApplicationUser user, string role);
        Task<IdentityResult> RemoverRoleAsync(ApplicationRole role);
        Task<IList<string>> ObterNomeDasRolesPorUsuarioAsync(ApplicationUser user);
        Task<ApplicationRole?> ObterRolePorId(string id);
        Task<ApplicationRole?> ObterRolePorNomeAsync(string nome);
        Task<IEnumerable<ApplicationRole>> ObterSystemIdDasRolesPorUsuarioAsync(IEnumerable<string> nomes);
        Task<IList<Claim>> ObterClaimsRoleAsync(ApplicationRole role);
        Task<IList<ApplicationRole>> ObterRolesPorSistemIdAsync(string systemId);

        // UserManager
        Task<bool> isEmailConfirmed(ApplicationUser user);
        Task<string> GeraTokenReset(ApplicationUser user);
        Task<IdentityResult> ResetarSenha(ApplicationUser user, string token, string newPassword);
    }
}