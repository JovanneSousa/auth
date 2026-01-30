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
        public async Task<ActionResult<LoginResponseViewModel>> Registrar(RegisterUserViewModel registerUser) =>
            CustomResponse(new { token = await _usuarioService.AdicionarUsuarioAsync(registerUser) });

        [HttpPost("login")]
        public async Task<ActionResult<LoginResponseViewModel>> Login(LoginUserViewModel loginUser) =>
            CustomResponse(new { token = await _usuarioService.LogarUsuarioAsync(loginUser) });

        [HttpGet("wake-up")]
        public ActionResult WakeUp() =>
            CustomResponse("A api está awake");

        [HttpPost("forgot-password")]
        public async Task<ActionResult<string>> ForgotPassword(string email)
            => CustomResponse(await _usuarioService.GerarTokenResetSenha(email));

        [HttpPost("nova-senha")]
        public async Task<ActionResult<bool>> ResetarSenha(string email, string token, string password)
            => CustomResponse(await _usuarioService.ResetarSenha(email, token, password));
    }
}
