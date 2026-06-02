using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Auth.Infra.Identity;

namespace Auth.Infra.Interfaces
{
    /// <summary>
    /// Interface de repositório para gestão de identidade, usuários e permissões.
    /// Abstrai as operações do ASP.NET Core Identity.
    /// </summary>
    public interface IAuthRepository
    {
        // Usuarios
        
        /// <summary>
        /// Obtém um usuário através do seu endereço de e-mail.
        /// </summary>
        Task<ApplicationUser?> ObterUsuarioPorEmailAsync(string email);

        /// <summary>
        /// Obtém um usuário através do seu identificador único (Id).
        /// </summary>
        Task<ApplicationUser?> ObterUsuarioPorIdAsync(string id);

        /// <summary>
        /// Lista todos os usuários cadastrados na base de autenticação.
        /// </summary>
        Task<IEnumerable<ApplicationUser>> ObterTodosAuthUserAsync();

        /// <summary>
        /// Cria um novo usuário na base com a senha fornecida.
        /// </summary>
        Task<IdentityResult> AdicionarUsuarioAsync(ApplicationUser user, string password);

        /// <summary>
        /// Remove um usuário permanentemente da base de dados.
        /// </summary>
        Task<IdentityResult> DeleteAsync(ApplicationUser usuario);

        //Claims

        /// <summary>
        /// Adiciona uma declaração (Claim) a um perfil (Role) específico.
        /// </summary>
        Task<IdentityResult> SalvaRoleClaim(ApplicationRole role, Claim claim);

        /// <summary>
        /// Remove uma declaração (Claim) de um perfil (Role).
        /// </summary>
        Task<IdentityResult> ExcluirRoleClaim(ApplicationRole role, Claim claim);

        /// <summary>
        /// Obtém todas as Claims associadas diretamente a um usuário.
        /// </summary>
        Task<IList<Claim>> ObterClaimsAsync(ApplicationUser user);

        /// <summary>
        /// Busca as Roles e suas respectivas Claims a partir de uma lista de identificadores de Roles.
        /// </summary>
        Task<IList<ApplicationRole>> ObterClaimsPorRoleIdsAsync(List<string> rolesIds);

        // Roles

        /// <summary>
        /// Associa um usuário a um nome de perfil (Role).
        /// </summary>
        Task<IdentityResult> SalvaRoleAsync(ApplicationUser user, string role);

        /// <summary>
        /// Remove um perfil (Role) da base de dados.
        /// </summary>
        Task<IdentityResult> RemoverRoleAsync(ApplicationRole role);

        /// <summary>
        /// Retorna os nomes das Roles vinculadas a um determinado usuário.
        /// </summary>
        Task<IList<string>> ObterNomeDasRolesPorUsuarioAsync(ApplicationUser user);

        /// <summary>
        /// Obtém um perfil (Role) pelo seu identificador único.
        /// </summary>
        Task<ApplicationRole?> ObterRolePorId(string id);

        /// <summary>
        /// Obtém um perfil (Role) pelo seu nome normalizado.
        /// </summary>
        Task<ApplicationRole?> ObterRolePorNomeAsync(string nome);

        /// <summary>
        /// Obtém as instâncias de ApplicationRole (incluindo SystemId) a partir de uma lista de nomes de roles.
        /// </summary>
        Task<IEnumerable<ApplicationRole>> ObterSystemIdDasRolesPorUsuarioAsync(IEnumerable<string> nomes);

        /// <summary>
        /// Obtém todas as Claims associadas a um perfil (Role) específico.
        /// </summary>
        Task<IList<Claim>> ObterClaimsRoleAsync(ApplicationRole role);

        /// <summary>
        /// Lista todas as Roles vinculadas a um sistema específico.
        /// </summary>
        Task<IList<ApplicationRole>> ObterRolesPorSistemIdAsync(string systemId);

        // UserManager

        /// <summary>
        /// Verifica se o e-mail do usuário já foi confirmado.
        /// </summary>
        Task<bool> isEmailConfirmed(ApplicationUser user);

        /// <summary>
        /// Gera um token de segurança para o processo de redefinição de senha.
        /// </summary>
        Task<string> GeraTokenReset(ApplicationUser user);

        /// <summary>
        /// Redefine a senha do usuário utilizando um token de segurança válido.
        /// </summary>
        Task<IdentityResult> ResetarSenha(ApplicationUser user, string token, string newPassword);
    }
}