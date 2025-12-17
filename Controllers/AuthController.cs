using auth.Controllers;
using auth.Interfaces;
using auth.Models;
using auth.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace fin_api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : MainController
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtSettings _jwtSettings;
        private readonly IUsuarioService _usuarioService;


        public AuthController
            (
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IOptions<JwtSettings> jwtSettings, 
            INotificador notificador,
            IUsuarioService usuarioService
            ) : base(notificador)
        {
            _jwtSettings = jwtSettings.Value;
            _signInManager = signInManager;
            _userManager = userManager;
            _usuarioService = usuarioService;
        }

        [HttpPost("registrar")]
        public async Task<ActionResult> Registrar(RegisterUserViewModel registerUser) =>
            CustomResponse(new { token = await _usuarioService.AdicionarUsuarioAsync(registerUser) });

        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUser) =>
            CustomResponse(new { token = await _usuarioService.LogarUsuarioAsync(loginUser) });

        [HttpGet("wake-up")]
        public ActionResult WakeUp()
        {
            return Ok("API is awake!");
        } 
    }
}
