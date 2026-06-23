using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Utils.Extensions;

namespace Auth.Api.Controllers
{
    /// <summary>
    /// Controller responsável pela gestão de ecossistemas (sistemas), perfis (roles) e permissões (claims).
    /// </summary>
    [Route("/api/sistema")]
    [Authorize]
    public class SistemaController : ApiController
    {
        private readonly ISystemService _systemService;
        public SistemaController(
            INotificador notificador, 
            ISystemService systemService
            ) 
            : base(notificador)
        {
            _systemService = systemService;
        }

        // Sistemas

        /// <summary>
        /// Cadastra um novo sistema na plataforma.
        /// </summary>
        /// <param name="sistema">Dados do sistema a ser criado.</param>
        /// <returns>Booleano indicando sucesso.</returns>
        [HttpPost]
        public async Task<ActionResult<bool>> CriarSistema(SystemViewModel sistema) 
            => CustomResponse(await _systemService.AdicionaSistemaAsync(sistema));

        /// <summary>
        /// Obtém a listagem de todos os sistemas cadastrados e seus detalhes.
        /// </summary>
        /// <returns>Lista de sistemas.</returns>
        [HttpGet]
        public async Task<ActionResult<SystemViewModel>> ListarSistemas()
            => CustomResponse(await _systemService.ObterTodosSistemasAsync());

        /// <summary>
        /// Atualiza os dados (Nome/URL) de um sistema existente.
        /// </summary>
        /// <param name="sistema">Dados atualizados do sistema.</param>
        /// <returns>Booleano indicando sucesso.</returns>
        [HttpPut]
        public async Task<ActionResult<bool>> AtualizaSistema(SystemViewModel sistema)
            => CustomResponse(await _systemService.AtualizaSistemaAsync(sistema));

        // Roles

        /// <summary>
        /// Adiciona um novo perfil (Role) vinculado a um sistema.
        /// </summary>
        /// <param name="role">Dados do perfil.</param>
        /// <returns>Booleano indicando sucesso.</returns>
        [HttpPost("roles")]
        public async Task<ActionResult<bool>> AdicionarRole(ApplicationRoleViewModel role)
            => CustomResponse(await _systemService.AdicionaRole(role));

        /// <summary>
        /// Remove um perfil do sistema, validando se existem claims associadas.
        /// </summary>
        /// <param name="roleId">ID do perfil a ser removido.</param>
        /// <returns>Booleano indicando sucesso.</returns>
        [HttpDelete("roles/remover/{roleId}")]
        public async Task<ActionResult<bool>> RemoverRole(string roleId)
            => CustomResponse(await _systemService.RemoverRole(roleId));

        // Claims

        /// <summary>
        /// Associa uma nova permissão (Claim) a um perfil específico.
        /// </summary>
        /// <param name="claim">Dados da permissão e Role associada.</param>
        /// <returns>Booleano indicando sucesso.</returns>
        [HttpPost("claim")]
        public async Task<ActionResult<bool>> AdicionarClaim(ApplicationClaimViewModel claim)
            => CustomResponse(await _systemService.AdicionaClaim(claim));

        /// <summary>
        /// Remove uma permissão específica de um perfil.
        /// </summary>
        /// <param name="roleId">ID do perfil.</param>
        /// <param name="claimValue">Valor da permissão a ser removida.</param>
        /// <returns>Booleano indicando sucesso.</returns>
        [HttpDelete("claim/excluir/{roleId}/{claimValue}")]
        public async Task<ActionResult<bool>> ExcluirClaim(string roleId, string claimValue)
            => CustomResponse(await _systemService.RemoveClaim(roleId, claimValue));
    }
}
