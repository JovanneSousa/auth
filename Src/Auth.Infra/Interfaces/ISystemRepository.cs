using Auth.Domain.Entities;
using Auth.Domain.ViewModel;
using Auth.Infra.Identity;

namespace Auth.Infra.Interfaces
{
    /// <summary>
    /// Interface de repositório para gestão dos sistemas satélites e suas configurações de acesso.
    /// </summary>
    public interface ISystemRepository
    {
        /// <summary>
        /// Registra um novo sistema na base de dados.
        /// </summary>
        Task<bool> AdicionarAsync(SystemEntity system);

        /// <summary>
        /// Atualiza as informações de um sistema existente.
        /// </summary>
        Task<bool> AtualizarAsync(SystemEntity system);

        /// <summary>
        /// Lista todos os sistemas cadastrados no ecossistema.
        /// </summary>
        Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync();

        /// <summary>
        /// Retorna os sistemas aos quais um usuário tem acesso, baseado em suas roles.
        /// </summary>
        Task<IEnumerable<SystemEntity>> ObterSistemasPorRolesAsync(IEnumerable<string> role);

        /// <summary>
        /// Busca um sistema através do seu nome.
        /// </summary>
        Task<SystemEntity?> ObterSistemaPorNome(string nome);

        /// <summary>
        /// Busca um sistema através do seu identificador único.
        /// </summary>
        Task<SystemEntity?> ObterSistemaPorId(string id);

        /// <summary>
        /// Adiciona uma nova Role vinculada a um sistema.
        /// </summary>
        Task<bool> AdicionaRole(ApplicationRole role);
    }
}
