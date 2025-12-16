using auth.Controllers;
using auth.Interfaces;
using auth.Models;
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


        public AuthController
            (
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IOptions<JwtSettings> jwtSettings, INotificador notificador
            ) : base(notificador)
        {
            _jwtSettings = jwtSettings.Value;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpPost("registrar")]
        public async Task<ActionResult> Registrar(RegisterUserViewModel registerUser)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            var user = new IdentityUser
            {
                UserName = registerUser.Nome + "-" + Guid.NewGuid().ToString(),
                Email = registerUser.Email,
                EmailConfirmed = true
            };

            var usuarioPorEmail = await _userManager.FindByEmailAsync(registerUser.Email);
            var usuarioPorNome = await _userManager.FindByNameAsync(registerUser.Nome);

            if (usuarioPorEmail != null || usuarioPorNome != null) return Problem("Usuário já cadastrado");

            var result = await _userManager.CreateAsync(user, registerUser.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                return Ok(new { token = await GerarJwt(registerUser.Email) });
            }

            return Problem("Falha ao registrar o usuário");
        }

        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUser)
        {
            var user = await _userManager.FindByEmailAsync(loginUser.Email);

            if (user == null)
            {
                _notificador.Handle(new Notificacao("usuário ou senha incorretos!"));
                return CustomResponse();
            };

            var result = await _signInManager.PasswordSignInAsync(user.UserName, loginUser.Password, false, true);

            if (!result.Succeeded)
            {
                _notificador.Handle(new Notificacao("usuário ou senha incorretos!"));
                return CustomResponse();
            }

            return CustomResponse(new { token = await GerarJwt(loginUser.Email) });
        }

        [HttpGet("wake-up")]
        public ActionResult WakeUp()
        {
            return Ok("API is awake!");
        }

        private async Task<LoginResponseViewModel> GerarJwt(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);
            var userRoles = await _userManager.GetRolesAsync(user);
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim("role", userRole));
            }

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);


            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Segredo);

            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Issuer = _jwtSettings.Emissor,
                Audience = _jwtSettings.Audiencia,
                Expires = DateTime.UtcNow.AddHours(_jwtSettings.ExpiracaoHoras),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            });

            var encodedToken = tokenHandler.WriteToken(token);

            var response = new LoginResponseViewModel
            {
                AccessToken = encodedToken,
                ExpiresIn = TimeSpan.FromHours(_jwtSettings.ExpiracaoHoras).TotalSeconds,
                UserToken = new UserTokenViewModel
                {
                    Id = user.Id,
                    Name = user.UserName.Split("-")[0],
                    Claims = claims.Select(c => new ClaimViewModel { Type = c.Type, Value = c.Value }).ToList()
                }
            };
            return response;
        }
    }
}
