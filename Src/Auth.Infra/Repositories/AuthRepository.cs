using Auth.Application.Repositories;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Auth.Infra.Repositories
{
    public class AuthRepository : BaseRepository, IAuthRepository
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
            await ExecuteAsync(async () => await _userManager.CreateAsync(user, password));
        public async Task<IdentityUser?> ObterUsuarioPorEmailAsync(string email) =>
            await ExecuteAsync(async () => await _userManager.FindByEmailAsync(email));
        public async Task<IdentityResult> DeleteAsync(IdentityUser usuario) =>
            await ExecuteAsync(async () => await _userManager.DeleteAsync(usuario));
        public async Task<IEnumerable<IdentityUser>> ObterTodosAuthUserAsync() =>
            await ExecuteAsync(async () => await _userManager.Users.AsNoTracking().ToListAsync());

        public async Task<IList<Claim>> ObterClaimsAsync(IdentityUser user) =>
            await ExecuteAsync(async () => await _userManager.GetClaimsAsync(user));
        public async Task<IdentityResult> SalvaClaimsAsync(IdentityUser user, IList<Claim> claims) =>
            await ExecuteAsync(async () => await _userManager.AddClaimsAsync(user, claims));

        public async Task<IList<string>> ObterRolesAsync(IdentityUser user) =>
            await ExecuteAsync(async () => await _userManager.GetRolesAsync(user));
        public async Task<IdentityRole> ObterRolePorNomeAsync(string nome) =>
            await ExecuteAsync(async () => await _roleManager.FindByNameAsync(nome));
        public async Task<IdentityResult> SalvaRoleAsync(IdentityUser user, string role) =>
            await ExecuteAsync(async () => await _userManager.AddToRoleAsync(user, role));
        public async Task<IList<Claim>> ObterClaimsRoleAsync(IdentityRole role) =>
            await ExecuteAsync(async () => await _roleManager.GetClaimsAsync(role));

        public async Task<string> GeraTokenReset(IdentityUser user) =>
            await ExecuteAsync(async () => await _userManager.GeneratePasswordResetTokenAsync(user));

        public async Task<bool> isEmailConfirmed(IdentityUser user) =>
            await ExecuteAsync(async () => await _userManager.IsEmailConfirmedAsync(user));

        public async Task<IdentityResult> ResetarSenha(IdentityUser user, string token, string newPassword) =>
            await ExecuteAsync(async () => await _userManager.ResetPasswordAsync(user, token, newPassword));
    }
}
