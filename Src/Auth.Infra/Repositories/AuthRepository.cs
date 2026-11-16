using Auth.Application.Repositories;
using Auth.Domain.Entities;
using Auth.Infra.Data;
using Auth.Infra.Identity;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Auth.Infra.Repositories
{
    /// <summary>
    /// Repositório de infraestrutura para gestão de usuários, perfis e permissões utilizando ASP.NET Identity.
    /// Encapsula operações do UserManager e RoleManager com tratamento de exceções de banco de dados.
    /// </summary>
    public class AuthRepository : BaseRepository, IAuthRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly ApplicationDbContext _context;
        public AuthRepository(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            ApplicationDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
        }

        // Refresh token
        public async Task<bool> updateRefreshToken(RefreshToken newRefreshToken)
            => await ExecuteAsync(async () =>
            {
                await _context.RefreshTokens
                    .Where(rt => rt.UserName == newRefreshToken.UserName)
                    .ExecuteDeleteAsync();
                await _context.RefreshTokens.AddAsync(newRefreshToken);
                await _context.SaveChangesAsync();
                return true;
            });

        public async Task<RefreshToken?> getRefreshToken(Guid refreshToken)
            => await ExecuteAsync(async () =>
                    await _context.RefreshTokens.AsNoTracking().
                        FirstOrDefaultAsync(rt => rt.Token == refreshToken));

        // Usuarios
        public async Task<IdentityResult> AdicionarUsuarioAsync(ApplicationUser user, string password) =>
            await ExecuteAsync(async () => await _userManager.CreateAsync(user, password));
        public async Task<ApplicationUser?> ObterUsuarioPorEmailAsync(string email) =>
            await ExecuteAsync(async () => await _userManager.FindByEmailAsync(email));
        public async Task<ApplicationUser?> ObterUsuarioPorIdAsync(string id) =>
            await ExecuteAsync(async () => await _userManager.FindByIdAsync(id));
        public async Task<IdentityResult> DeleteAsync(ApplicationUser usuario) =>
            await ExecuteAsync(async () =>
            {
                if (!string.IsNullOrWhiteSpace(usuario.UserName))
                {
                    await _context.RefreshTokens
                        .Where(rt => rt.UserName == usuario.UserName)
                        .ExecuteDeleteAsync();
                }

                return await _userManager.DeleteAsync(usuario);
            });
        public async Task<IEnumerable<ApplicationUser>> ObterTodosAuthUserAsync() =>
            await ExecuteAsync(async () => await _userManager.Users.AsNoTracking().ToListAsync());

        // Claims
        public async Task<IdentityResult> SalvaRoleClaim(ApplicationRole role, Claim claim) =>
            await ExecuteAsync(async () => await _roleManager.AddClaimAsync(role, claim));
        public async Task<IdentityResult> ExcluirRoleClaim(ApplicationRole role, Claim claim) =>
            await ExecuteAsync(async () => await _roleManager.RemoveClaimAsync(role, claim));
        public async Task<IList<Claim>> ObterClaimsRoleAsync(ApplicationRole role) =>
            await ExecuteAsync(async () => await _roleManager.GetClaimsAsync(role));
        public async Task<IList<Claim>> ObterClaimsPorUsuarioAsync(ApplicationUser user) =>
            await ExecuteAsync(async () =>
            {
                return await (from rc in _context.RoleClaims.AsNoTracking()
                              join ur in _context.UserRoles.AsNoTracking() on rc.RoleId equals ur.RoleId
                              where ur.UserId == user.Id
                              select new Claim(rc.ClaimType!, rc.ClaimValue!))
                    .ToListAsync();
            });
        public async Task<IList<ApplicationRole>> ObterClaimsPorRoleIdsAsync(List<string> rolesIds) =>
            await ExecuteAsync(async () => 
                await _context.Roles
                    .AsNoTracking()
                    .Where(r => rolesIds.Contains(r.Id))
                    .ToListAsync());

        // Roles
        public async Task<IList<string>> ObterNomeDasRolesPorUsuarioAsync(ApplicationUser user) =>
            await ExecuteAsync(async () => await _userManager.GetRolesAsync(user));
        public async Task<ApplicationRole?> ObterRolePorId(string id)
            => await _roleManager.FindByIdAsync(id);
        public async Task<ApplicationRole?> ObterRolePorNomeAsync(string nome) =>
            await ExecuteAsync(async () => await _roleManager.FindByNameAsync(nome));
        public async Task<IList<ApplicationRole>> ObterRolesPorSistemIdAsync(string systemId) =>
            await ExecuteAsync(async () => 
                await _context.Roles
                    .AsNoTracking()
                    .Where(r => r.SystemId == systemId)
                    .ToListAsync());
        public async Task<IEnumerable<ApplicationRole>> ObterSystemIdDasRolesPorUsuarioAsync(IEnumerable<string> nomes)
            => await ExecuteAsync(async () =>
                await _context.Roles
                    .AsNoTracking()
                    .Where(c => nomes.Contains(c.Name))
                    .ToListAsync());
        public async Task<IdentityResult> SalvaRoleAsync(ApplicationUser user, string role) =>
            await ExecuteAsync(async () => await _userManager.AddToRoleAsync(user, role));
        public async Task<IdentityResult> RemoverRoleAsync(ApplicationRole role)
            => await ExecuteAsync(async () => await _roleManager.DeleteAsync(role));

        public async Task<ApplicationRole?> ObterRolePorSistemaENomeAsync(string system, string roleName) =>
            await ExecuteAsync(async () =>
            {
                var normalizedRole = roleName.Trim().ToUpperInvariant();
                var normalizedSystem = system.Trim().ToUpperInvariant();

                var rolesWithName = await _context.Roles
                    .AsNoTracking()
                    .Include(r => r.System)
                    .Where(r => r.NormalizedName == normalizedRole || (r.Name != null && r.Name.ToUpper() == normalizedRole))
                    .ToListAsync();

                if (rolesWithName.Count == 0)
                    return null;

                var matchedBySystem = rolesWithName.FirstOrDefault(r =>
                    r.SystemId.Equals(normalizedSystem, StringComparison.OrdinalIgnoreCase) ||
                    (r.System != null && (
                        r.System.Name.Equals(normalizedSystem, StringComparison.OrdinalIgnoreCase) ||
                        r.System.Name.StartsWith(normalizedSystem, StringComparison.OrdinalIgnoreCase))));

                if (matchedBySystem is not null)
                    return matchedBySystem;

                return rolesWithName.Count == 1 ? rolesWithName[0] : null;
            });

        public async Task<bool> UsuarioPossuiRolePorIdAsync(string userId, string roleId) =>
            await ExecuteAsync(async () =>
                await _context.UserRoles.AnyAsync(ur => ur.UserId == userId && ur.RoleId == roleId));

        public async Task<bool> SalvaUserRolePorIdAsync(string userId, string roleId) =>
            await ExecuteAsync(async () =>
            {
                await _context.UserRoles.AddAsync(new IdentityUserRole<string>
                {
                    UserId = userId,
                    RoleId = roleId
                });
                await _context.SaveChangesAsync();
                return true;
            });

        public async Task<bool> SistemaExisteAsync(string system) =>
            await ExecuteAsync(async () =>
            {
                var normalized = system.Trim().ToUpperInvariant();
                var prefix = normalized.EndsWith(':') ? normalized : $"{normalized}:";

                return await _context.SystemEntity.AnyAsync(s =>
                           s.Id.ToUpper() == normalized ||
                           s.Name.ToUpper() == normalized ||
                           s.Name.ToUpper().StartsWith(normalized)) ||
                       await _context.RoleClaims.AnyAsync(rc =>
                           rc.ClaimType == "permission" &&
                           rc.ClaimValue != null &&
                           rc.ClaimValue.ToUpper().StartsWith(prefix));
            });

        // User Manager
        public async Task<string> GeraTokenReset(ApplicationUser user) =>
            await ExecuteAsync(async () => await _userManager.GeneratePasswordResetTokenAsync(user));
        public async Task<bool> isEmailConfirmed(ApplicationUser user) =>
            await ExecuteAsync(async () => await _userManager.IsEmailConfirmedAsync(user));
        public async Task<IdentityResult> ResetarSenha(ApplicationUser user, string token, string newPassword) =>
            await ExecuteAsync(async () => await _userManager.ResetPasswordAsync(user, token, newPassword));


    }
}
