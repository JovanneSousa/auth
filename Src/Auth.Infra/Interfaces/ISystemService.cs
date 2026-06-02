using Auth.Domain.ViewModel;
namespace Auth.Infra.Interfaces
{
    /// <summary>
    /// Interface que define as operações de negócio para gestão de sistemas e permissões.
    /// </summary>
    public interface ISystemService
    {
        // Sistemas
        
        /// <summary>
        /// Cadastra um novo sistema na plataforma.
        /// </summary>
        Task<bool> AdicionaSistemaAsync(SystemViewModel sistema);

        /// <summary>
        /// Atualiza dados básicos de um sistema.
        /// </summary>
        Task<bool> AtualizaSistemaAsync(SystemViewModel sistema);

        /// <summary>
        /// Remove um sistema da base (Não implementado).
        /// </summary>
        Task<bool> RemoveSistemaAsync(string sistemaId);

        /// <summary>
        /// Retorna todos os sistemas com suas respectivas permissões.
        /// </summary>
        Task<List<SystemViewModel>> ObterTodosSistemasAsync();

        // Roles
        
        /// <summary>
        /// Adiciona um perfil de acesso a um sistema.
        /// </summary>
        Task<bool> AdicionaRole(ApplicationRoleViewModel roleVm);

        /// <summary>
        /// Remove um perfil de acesso.
        /// </summary>
        Task<bool> RemoverRole(string roleId);


        // Claims
        
        /// <summary>
        /// Adiciona uma claim de permissão a um perfil.
        /// </summary>
        Task<bool> AdicionaClaim(ApplicationClaimViewModel claim);

        /// <summary>
        /// Remove uma claim de permissão de um perfil.
        /// </summary>
        Task<bool> RemoveClaim(string roleId, string claimValue);
    }
}
