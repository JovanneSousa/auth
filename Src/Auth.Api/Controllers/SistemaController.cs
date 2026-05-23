using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers
{
    [Route("/api/sistema")]
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

        [HttpPost]
        public async Task<ActionResult<bool>> CriarSistema(SystemViewModel sistema) 
            => CustomResponse(await _systemService.AdicionaSistemaAsync(sistema));

        [HttpGet]
        public async Task<ActionResult<SystemViewModel>> ListarSistemas()
            => CustomResponse(await _systemService.ObterTodosSistemasAsync());

        [HttpPut]
        public async Task<ActionResult<bool>> AtualizaSistema(SystemViewModel sistema)
            => CustomResponse(await _systemService.AtualizaSistemaAsync(sistema));

        // Roles

        [HttpPost("roles")]
        public async Task<ActionResult<bool>> AdicionarRole(ApplicationRoleViewModel role)
            => CustomResponse(await _systemService.AdicionaRole(role));

        [HttpDelete("roles/remover/{roleId}")]
        public async Task<ActionResult<bool>> RemoverRole(string roleId)
            => CustomResponse(await _systemService.RemoverRole(roleId));

        // Claims

        [HttpPost("claim")]
        public async Task<ActionResult<bool>> AdicionarClaim(ApplicationClaimViewModel claim)
            => CustomResponse(await _systemService.AdicionaClaim(claim));

        [HttpDelete("claim/excluir/{roleId}/{claimValue}")]
        public async Task<ActionResult<bool>> ExcluirClaim(string roleId, string claimValue)
            => CustomResponse(await _systemService.RemoveClaim(roleId, claimValue));
    }
}
