using Auth.Application.Data;
using Auth.Application.Repositories;
using Auth.Domain.Entities;
using Auth.Infra.Identity;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Auth.Infra.Repositories
{
    public class AuthRepository : BaseRepository, IAuthRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly ApplicationDbContext _context;
        public AuthRepository(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager
,
            ApplicationDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
        }

        // Usuarios
        public async Task<IdentityResult> AdicionarUsuarioAsync(ApplicationUser user, string password) =>
            await ExecuteAsync(async () => await _userManager.CreateAsync(user, password));
        public async Task<ApplicationUser?> ObterUsuarioPorEmailAsync(string email) =>
            await ExecuteAsync(async () => await _userManager.FindByEmailAsync(email));
        public async Task<ApplicationUser?> ObterUsuarioPorIdAsync(string id) =>
            await ExecuteAsync(async () => await _userManager.FindByIdAsync(id));
        public async Task<IdentityResult> DeleteAsync(ApplicationUser usuario) =>
            await ExecuteAsync(async () => await _userManager.DeleteAsync(usuario));
        public async Task<IEnumerable<ApplicationUser>> ObterTodosAuthUserAsync() =>
            await ExecuteAsync(async () => await _userManager.Users.AsNoTracking().ToListAsync());

        // Claims
        public async Task<IList<Claim>> ObterClaimsAsync(ApplicationUser user) =>
            await ExecuteAsync(async () => await _userManager.GetClaimsAsync(user));
        public async Task<IdentityResult> SalvaClaimsAsync(ApplicationUser user, IList<Claim> claims) =>
            await ExecuteAsync(async () => await _userManager.AddClaimsAsync(user, claims));
        public async Task<IList<Claim>> ObterClaimsRoleAsync(ApplicationRole role) =>
            await ExecuteAsync(async () => await _roleManager.GetClaimsAsync(role));
        public async Task<IList<ApplicationRole>> ObterClaimsPorRoleIdsAsync(List<string> rolesIds) =>
            await ExecuteAsync(async () => 
                await _context.Roles
                    .Where(r => rolesIds.Contains(r.Id))
                    .ToListAsync());

        // Roles
        public async Task<IList<string>> ObterNomeDasRolesPorUsuarioAsync(ApplicationUser user) =>
            await ExecuteAsync(async () => await _userManager.GetRolesAsync(user));
        public async Task<ApplicationRole> ObterRolePorNomeAsync(string nome) =>
            await ExecuteAsync(async () => await _roleManager.FindByNameAsync(nome));
        public async Task<IList<ApplicationRole>> ObterRolesPorSistemIdAsync(string systemId) =>
            await ExecuteAsync(async () => 
                await _context.Roles
                    .Where(r => r.SystemId == systemId)
                    .ToListAsync());
        public async Task<IEnumerable<ApplicationRole>> ObterSystemIdDasRolesPorUsuarioAsync(IEnumerable<string> nomes)
            => await ExecuteAsync(async () =>
                await _context.Roles
                    .Where(c => nomes.Contains(c.Name))
                    .ToListAsync());
        public async Task<IdentityResult> SalvaRoleAsync(ApplicationUser user, string role) =>
            await ExecuteAsync(async () => await _userManager.AddToRoleAsync(user, role));


        // User Manager
        public async Task<string> GeraTokenReset(ApplicationUser user) =>
            await ExecuteAsync(async () => await _userManager.GeneratePasswordResetTokenAsync(user));
        public async Task<bool> isEmailConfirmed(ApplicationUser user) =>
            await ExecuteAsync(async () => await _userManager.IsEmailConfirmedAsync(user));
        public async Task<IdentityResult> ResetarSenha(ApplicationUser user, string token, string newPassword) =>
            await ExecuteAsync(async () => await _userManager.ResetPasswordAsync(user, token, newPassword));
    }
}
