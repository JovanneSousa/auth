using auth.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace auth.Domain.Repositories;

public class UsuarioRepository : IUsuarioRepository
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    public UsuarioRepository(
        UserManager<IdentityUser> userManager, 
        SignInManager<IdentityUser> signInManager
        )
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    public async Task<SignInResult> LogarComSenha(string user, string password)
        => await _signInManager.PasswordSignInAsync(user, password, false, true);
    public async Task LogarAsync(IdentityUser user)
        => await _signInManager.SignInAsync(user, false);

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

    public async Task<IdentityResult> ResetSenha(IdentityUser user, string token, string password) =>
        await _userManager.ResetPasswordAsync(user, token, password);
}
