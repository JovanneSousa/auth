using auth.Controllers;
using auth.Domain.Interfaces;
using auth.DTOs;
using auth.Infra.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
namespace fin_api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : MainController
    {
        private readonly IUsuarioService _usuarioService;


        public AuthController
            (
            IOptions<JwtSettings> jwtSettings,
            INotificador notificador,
            IUsuarioService usuarioService
            ) : base(notificador)
        {
            _usuarioService = usuarioService;
        }

        [HttpPost("registrar")]
        public async Task<ActionResult> Registrar(RegisterUserViewModel registerUser) =>
            CustomResponse(new { token = await _usuarioService.AdicionarUsuarioAsync(registerUser) });

        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUser) =>
            CustomResponse(new { token = await _usuarioService.LogarUsuarioAsync(loginUser) });

        [HttpGet("wake-up")]
        public ActionResult WakeUp() =>
            CustomResponse("A api está awake");

        [HttpPost("forgot-password")]
        public async Task<ActionResult<string>> ForgotPassword(ForgotPassViewModel data)
            => CustomResponse(await _usuarioService.GerarTokenResetarSenha(data));

        [HttpPost("reset-pass")]
        public async Task<ActionResult<string>> ResetPass(ResetPassViewModel data)
            => CustomResponse(await _usuarioService.RecuperarSenha(data));
    }
}
