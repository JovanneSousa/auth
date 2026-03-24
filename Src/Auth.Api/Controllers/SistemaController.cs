using Auth.Domain.Entities;
using Auth.Infra.Interfaces;
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

        [HttpPost]
        public async Task<ActionResult<bool>> CriarSistema(SystemEntity sistema) 
            => CustomResponse(await _systemService.AdicionaSistemaAsync(sistema));

        [HttpGet]
        public async Task<ActionResult<SystemEntity>> ListarSistemas()
            => CustomResponse(await _systemService.ObterTodosSistemasAsync());
    }
}
