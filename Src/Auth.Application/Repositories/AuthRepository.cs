using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Auth.Application.Repositories;

public class AuthRepository : IAuthRepository
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    public AuthRepository(
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager
        )
    {
        _userManager = userManager;
        _roleManager = roleManager;
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
    public async Task<IdentityRole> ObterRolePorNomeAsync(string nome) =>
        await _roleManager.FindByNameAsync(nome);
    public async Task<IdentityResult> SalvaRoleAsync(IdentityUser user, string role) =>
        await _userManager.AddToRoleAsync(user, role);
    public async Task<IList<Claim>> ObterClaimsRoleAsync(IdentityRole role) =>
        await _roleManager.GetClaimsAsync(role);


    public async Task<string> GeraTokenReset(IdentityUser user) =>
        await _userManager.GeneratePasswordResetTokenAsync(user);

    public async Task<bool> isEmailConfirmed(IdentityUser user) =>
        await _userManager.IsEmailConfirmedAsync(user);

    public async Task<IdentityResult> ResetarSenha(IdentityUser user, string token, string newPassword) =>
        await _userManager.ResetPasswordAsync(user, token, newPassword);

    public async Task<IdentityResult> DeleteAsync(IdentityUser usuario) =>
        await _userManager.DeleteAsync(usuario);

    public async Task<IEnumerable<IdentityUser>> ObterTodosAuthUserAsync()
        => await _userManager.Users.AsNoTracking().ToListAsync();
}
