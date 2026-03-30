using Auth.Api.Controllers;
using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace fin_api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ApiController
    {
        private readonly IAuthService _authService;
        private readonly IHttpContextAccessor _acessor; 

        public AuthController
            (
            INotificador notificador,
            IAuthService authService,
            IHttpContextAccessor user
            ) : base(notificador)
        {
            _acessor = user; 
            _authService = authService;
        }

        [HttpPost("registrar")]
        public async Task<ActionResult> Registrar(RegisterUserViewModel registerUser) =>
            CustomResponse(new { token = await _authService.AdicionarUsuarioAsync(registerUser) });

        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUser)
        {
            var sheme = _acessor.HttpContext.Request.Scheme;
            var host = _acessor.HttpContext.Request.Host.ToString();
            return CustomResponse(new { token = await _authService.LogarUsuarioAsync(loginUser, sheme, host) });
        }

        [HttpGet("health")]
        public ActionResult WakeUp() =>
            Ok();

        [HttpPost("forgot-password")]
        public async Task<ActionResult<string>> ForgotPassword(ForgotPassViewModel data)
            => CustomResponse(await _authService.GerarTokenResetarSenha(data));

        [HttpPost("reset-pass")]
        public async Task<ActionResult<string>> ResetPass(ResetPassViewModel data)
            => CustomResponse(await _authService.RecuperarSenha(data));

        [HttpGet("listar-usuarios")]
        public async Task<ActionResult<IEnumerable<AuthUserViewModel>>> ListarUsuarios()
            => CustomResponse(await _authService.ListarAuthUser());

        [HttpGet("details-user/{id}")]
        public async Task<ActionResult<AuthUserViewModel>> ObterUsuarioPorId(string id) 
            => CustomResponse(await _authService.ObterUsuarioPorId(id));
    }
}
