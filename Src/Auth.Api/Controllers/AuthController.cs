using Auth.Api.Controllers;
using Auth.Application.DTOs;
using Auth.Application.Services;
using Auth.Infra.Identity;
using Auth.Infra.Notifications;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace fin_api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ApiController
    {
        private readonly IAuthService _authService;


        public AuthController
            (
            IOptions<JwtSettings> jwtSettings,
            INotificador notificador,
            IAuthService authService
            ) : base(notificador)
        {
            _authService = authService;
        }

        [HttpPost("registrar")]
        public async Task<ActionResult> Registrar(RegisterUserViewModel registerUser) =>
            CustomResponse(new { token = await _authService.AdicionarUsuarioAsync(registerUser) });

        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUser) =>
            CustomResponse(new { token = await _authService.LogarUsuarioAsync(loginUser) });

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
    }
}
