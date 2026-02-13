using auth.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace auth.Domain.Repositories;

public class UsuarioRepository : IUsuarioRepository
{
    private readonly UserManager<IdentityUser> _userManager;
    public UsuarioRepository(
        UserManager<IdentityUser> userManager
        )
    {
        _userManager = userManager;
    }

    public async Task<IdentityResult> AdicionarUsuarioAsync(IdentityUser user, string password) =>
        await _userManager.CreateAsync(user, password);

    public async Task<IList<Claim>> ObterClaimsAsync(IdentityUser user) =>
        await _userManager.GetClaimsAsync(user);

    public async Task<IdentityUser?> ObterUsuarioPorEmailAsync(string email) =>
        await _userManager.FindByEmailAsync(email);

    public async Task<IdentityResult> SalvaClaimsAsync(IdentityUser user, IList<Claim> claims) =>
        await _userManager.AddClaimsAsync(user, claims);

    public async Task<IList<string>> ObterRolesAsync(IdentityUser user) =>
        await _userManager.GetRolesAsync(user);

    public async Task<string> GeraTokenReset(IdentityUser user) =>
        await _userManager.GeneratePasswordResetTokenAsync(user);

    public async Task<bool> isEmailConfirmed(IdentityUser user) =>
        await _userManager.IsEmailConfirmedAsync(user);

    public async Task<IdentityResult> ResetarSenha(IdentityUser user, string token, string newPassword) =>
        await _userManager.ResetPasswordAsync(user, token, newPassword);

    public async Task<IdentityResult> DeleteAsync(IdentityUser usuario) =>
        await _userManager.DeleteAsync(usuario);
}
