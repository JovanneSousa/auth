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
            var user = new IdentityUser
            {
                UserName = registerUser.Nome + "-" + Guid.NewGuid().ToString(),
                Email = registerUser.Email,
                EmailConfirmed = true
            };

            var usuarioPorEmail = await _userManager.FindByEmailAsync(registerUser.Email);

            if (usuarioPorEmail == null) 
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);

                if (!result.Succeeded)
                {

                    foreach(var error in result.Errors)
                    {
                        _notificador.Handle(new Notificacao(error.Description));
                    }
                    _notificador.Handle(new Notificacao("Falha ao registrar o usuário"));
                    return CustomResponse();
                }

                var resultSalvaClaim = await SalvaUserClaims(user, registerUser);
                if (!resultSalvaClaim) return CustomResponse();

                await _signInManager.SignInAsync(user, false);
                return CustomResponse(new { token = await GerarJwt(registerUser.Email) });
            }

            var executaLogin = 
                await _signInManager.PasswordSignInAsync(usuarioPorEmail.UserName, registerUser.Password, false, true);
            if(!executaLogin.Succeeded)
            {
                _notificador.Handle(new Notificacao("A senha deve ser a mesma do outro sistema para a liberação de permissão!"));
                return CustomResponse();
            }

            var salvaClaims = await SalvaUserClaims(usuarioPorEmail, registerUser);
            if(!salvaClaims) return CustomResponse();

            await _signInManager.SignInAsync(user, false);
            return CustomResponse(new 
            { 
                token = await GerarJwt(user.Email) 
            });
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


        private async Task<bool> SalvaUserClaims(IdentityUser user, RegisterUserViewModel registerUser)
        {
            var claimsToAdd = await GeraListaDeClaims(user, registerUser);
            if (claimsToAdd == null) return false;

            var resultAddClaims = await _userManager.AddClaimsAsync(user, claimsToAdd);
            if(!resultAddClaims.Succeeded)
            {
                _notificador.Handle(new Notificacao("Falha ao salvar as permissões!"));
                return false;
            }
            return true;
        }

        private async Task<List<Claim>?> GeraListaDeClaims(IdentityUser user, RegisterUserViewModel registerUser)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var systemClaims = claims.FirstOrDefault(c =>
                c.Type == "permission" &&
                c.Value.StartsWith($"{registerUser.System.ToUpper()}"));

            if (systemClaims != null)
            {
                _notificador.Handle(new Notificacao("O usuário ja tem acesso a esse sistema!"));
                return null;
            }

            var permissions = ResolvePermissions(registerUser.System, registerUser.Profile);

            if (permissions == null)
            {
                _notificador.Handle(new Notificacao("Falha ao adicionar as permissões!"));
                return null;
            }

            var claimsToAdd = new List<Claim>();
            foreach (var permission in permissions)
            {
                claimsToAdd.Add(new Claim("permission", permission));
            }

            return claimsToAdd;
        }

        private IEnumerable<string>? ResolvePermissions(string system, string profile)
        {
            system = system.ToUpper();
            profile = profile.ToUpper();

            return (system, profile) switch
            {
                ("FINANCEIRO", "USUARIO") => new[]
                {
                    "FINANCEIRO:TRANSACAO_LISTAR",
                    "FINANCEIRO:TRANSACAO_CRIAR",
                    "FINANCEIRO:TRANSACAO_EXCLUIR",
                    "FINANCEIRO:TRANSACAO_EDITAR",
                    "FINANCEIRO:CATEGORIA_LISTAR",
                    "FINANCEIRO:CATEGORIA_CRIAR",
                    "FINANCEIRO:CATEGORIA_EXCLUIR",
                },

                _ => null
            };
        }
        
        private async Task<LoginResponseViewModel> GerarJwt(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            var claims = await ObterClaimsUsuarioAsync(user);
            var token = GerarToken(claims);

            return MontarLoginResponse(user, token, claims);
        }

        private async Task<List<Claim>> ObterClaimsUsuarioAsync(IdentityUser? user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            claims.AddRange(await _userManager.GetClaimsAsync(user));

            var roles = await _userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(role => new Claim("role", role)));

            return claims;
        }

        private string GerarToken(IEnumerable<Claim> claims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Segredo);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Issuer = _jwtSettings.Emissor,
                Audience = _jwtSettings.Audiencia,
                Expires = DateTime.UtcNow.AddHours(_jwtSettings.ExpiracaoHoras),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private LoginResponseViewModel MontarLoginResponse(IdentityUser user, string token, IEnumerable<Claim> claims)
        {
            return new LoginResponseViewModel
            {
                AccessToken = token,
                ExpiresIn = TimeSpan
            .FromHours(_jwtSettings.ExpiracaoHoras)
            .TotalSeconds,

                UserToken = new UserTokenViewModel
                {
                    Id = user.Id,
                    Name = user.UserName.Split('-')[0],
                    Claims = claims.Select(c => new ClaimViewModel
                    {
                        Type = c.Type,
                        Value = c.Value
                    }).ToList()
                }
            };
        }
    }
}
