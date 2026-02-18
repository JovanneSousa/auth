using auth.Domain.Entities;
using auth.Domain.Interfaces;
using auth.DTOs;
using auth.Infra.Identity;
using Bus;
using FluentValidation.Results;
using Messages;
using Messages.Integration;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FV = FluentValidation.Results;

namespace auth.Domain.Services;

public class UsuarioService : IUsuarioService
{
    private readonly IUsuarioRepository _usuarioRepository;
    private readonly INotificador _notificador;
    private readonly JwtSettings _jwtSettings;
    private readonly RabbitSettings _rabbitSettings;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly PermissionModel _permissions;
    private readonly IMessageBus _messageBus;
    private readonly string _frontUrl;

    public UsuarioService(
        IUsuarioRepository usuarioRepository, 
        INotificador notificador,
        IOptions<JwtSettings> jwtSettings,
        IOptions<RabbitSettings> rabbitSettings,
        SignInManager<IdentityUser> signInManager,
        PermissionModel permissions,
        IMessageBus messageBus,
        IOptions<FrontEndSettings> settings
        )
    {
        _permissions = permissions;
        _usuarioRepository = usuarioRepository;
        _notificador = notificador;
        _jwtSettings = jwtSettings.Value;
        _signInManager = signInManager;
        _messageBus = messageBus;
        _frontUrl = settings.Value.AllowedApps.First();
        _rabbitSettings = rabbitSettings.Value;
    }

    public async Task<bool> AdicionarUsuarioAsync(RegisterUserViewModel registerUser)
    {
        var usuarioExistente = 
            await _usuarioRepository.ObterUsuarioPorEmailAsync(registerUser.Email);

        IdentityUser user;

        if (usuarioExistente == null)
        {
            user = new IdentityUser
            {
                UserName = registerUser.Email,
                Email = registerUser.Email,
                EmailConfirmed = true
            };
            var created = await CriaUserIdentity(user, registerUser.Password, registerUser);
            if (!created) return false;
        } else
        {
            var executaLogin =
                await _signInManager.PasswordSignInAsync(usuarioExistente.UserName, registerUser.Password, false, true);
            if (!executaLogin.Succeeded)
            {
                _notificador.Handle(new Notificacao("A senha deve ser a mesma do outro sistema para a liberação de permissão!"));
                return false;
            }

            user = usuarioExistente;
        }

        var usuarioRegistrado = await RegistraUsuario(registerUser);
        if(!usuarioRegistrado.ValidationResult.IsValid || usuarioRegistrado == null) 
            return false;

        if (!await SalvaUserClaims(user, registerUser))
            return false;

        return true;
    }

    private async Task<ResponseMessage> RegistraUsuario(RegisterUserViewModel registerUser)
    {
        var usuario = await _usuarioRepository.ObterUsuarioPorEmailAsync(registerUser.Email);

        var usuarioRegistrado = new UsuarioRegistradoIntegrationEvent
        {
            Id = usuario.Id,
            Nome = registerUser.Nome,
            Email = usuario.Email
        };

        try
        {
            var usuarioResult = 
                await _messageBus.RequestAsync<UsuarioRegistradoIntegrationEvent, ResponseMessage>(usuarioRegistrado);

            if (!usuarioResult.ValidationResult.IsValid)
            {

                var errors = usuarioResult.ValidationResult.Errors;

                foreach (var error in errors)
                    _notificador.Handle(new Notificacao(error.ErrorMessage));

                return usuarioResult;
            }

            return usuarioResult;
        } catch
        {
            _notificador.Handle(new Notificacao("Erro ao cadastrar usuário no sistema"));
            return new ResponseMessage(
                    new ValidationResult(
                        [ 
                            new FV.ValidationFailure("", "Erro de integração") 
                        ]
                    )
                );
        }
    }

    private async Task<bool> CriaUserIdentity(IdentityUser user, string password, RegisterUserViewModel registerUser)
    {
        var result = await _usuarioRepository.AdicionarUsuarioAsync(user, password);

        if (!result.Succeeded)
        {
            _notificador.Handle(new Notificacao("Falha ao registrar o usuário"));
            return false;
        }

        return true;
    }

    public async Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser)
    {
        var user = await _usuarioRepository.ObterUsuarioPorEmailAsync(loginUser.Email);
        if (user == null)
        {
            _notificador.Handle(new Notificacao("usuário ou senha incorretos!"));
            return null;
        };

        var claims = await _usuarioRepository.ObterClaimsAsync(user);

        var result = await _signInManager.PasswordSignInAsync(user.UserName, loginUser.Password, false, true);
        if (!result.Succeeded)
        {
            _notificador.Handle(new Notificacao("usuário ou senha incorretos!"));
            return null;
        }

        var hasPermission = claims.Any(c =>
            c.Type == "permission" &&
            c.Value.StartsWith(loginUser.System.ToUpper())
            );
        if (!hasPermission)
        {
            _notificador.Handle(new Notificacao("Usuário não tem permissão nesse sistema!"));
            return null;
        }

        await _signInManager.SignInAsync(user, false);
        return await GerarJwt(user);
    }

    public async Task<bool> GerarTokenResetarSenha(ForgotPassViewModel data)
    {
        var user = await _usuarioRepository.ObterUsuarioPorEmailAsync(data.Email);
        if (user == null) return true;

        var confirmado = await _usuarioRepository.isEmailConfirmed(user);
        if (!confirmado) return true;

        var token = await _usuarioRepository.GeraTokenReset(user);

        var encodedEmail = Uri.EscapeDataString(data.Email);
        var encodedToken = Uri.EscapeDataString(token);

        var resetLink = $"{_frontUrl}/auth?email={encodedEmail}&token={encodedToken}";

        await _messageBus.PublishAsync(geraEmailEvent(data.Email, resetLink, user.Id));
        return true;
    }

    public async Task<bool> RecuperarSenha(ResetPassViewModel data)
    {
        if(string.IsNullOrEmpty(data.Email))
        {
            _notificador.Handle(new Notificacao("Email inválido!"));
            return false;
        }
        var user = await _usuarioRepository.ObterUsuarioPorEmailAsync(data.Email);
        if(user == null)
        {
            _notificador.Handle(new Notificacao("Usuário não encontrado!"));
            return false;
        }
        if (string.IsNullOrEmpty(data.Password) || string.IsNullOrEmpty(data.Token)) 
        {
            _notificador.Handle(new Notificacao("token inválido!"));
            return false;
        }
        var result = await _usuarioRepository.ResetarSenha(user, data.Token, data.Password);
        if (!result.Succeeded)
        {
            _notificador.Handle(new Notificacao("Houve um erro atualizando a senha!"));
            return false;
        }
        return true;
    }

    private EmailIntegrationEvent geraEmailEvent(string email, string resetLink, string userId)
        => new EmailIntegrationEvent
        {
            To = email,
            Type = "RESET",
            Subject = "Redefinição de senha",
            Body = $"Clique no link a seguir para redefinir sua senha: {resetLink}",
            EventId = Guid.NewGuid().ToString(),
            Metadata = new Metadados
            {
                retry = 0,
                UserId = userId,
                UserName = email
            }
        };

    private async Task<bool> SalvaUserClaims(IdentityUser user, RegisterUserViewModel registerUser)
    {
        var claimsToAdd = await GeraListaDeClaims(user, registerUser);
        if (claimsToAdd == null) return false;

        var resultAddClaims = await _usuarioRepository.SalvaClaimsAsync(user, claimsToAdd);
        if (!resultAddClaims.Succeeded)
        {
            _notificador.Handle(new Notificacao("Falha ao salvar as permissões!"));
            return false;
        }
        return true;
    }

    private async Task<List<Claim>?> GeraListaDeClaims(IdentityUser user, RegisterUserViewModel registerUser)
    {
        var claims = await _usuarioRepository.ObterClaimsAsync(user);
        var systemClaims = claims.FirstOrDefault(c =>
            c.Type == "permission" &&
            c.Value.StartsWith(registerUser.System.ToUpper())
            );

        if (systemClaims != null)
        {
            _notificador.Handle(new Notificacao("O usuário ja tem acesso a esse sistema!"));
            return null;
        }

        var permissions = ResolvePermissions(registerUser.System, registerUser.Profile);
        if (permissions == null) return null;

        return permissions.Select(p => new Claim("permission", p))
            .ToList();
    }
    private IEnumerable<string>? ResolvePermissions(string system, string profile)
    {
        system = system.ToUpper();
        profile = profile.ToUpper();

        if (!_permissions.Systems.TryGetValue(system, out var profiles))
        {
            _notificador.Handle(new Notificacao("Sistema não encontrado!"));
            return null;
        }
        if (!profiles.TryGetValue(profile, out var permissions))
        {
            _notificador.Handle(new Notificacao("Permissões não encontradas para esse perfil"));
            return null;
        }

        return permissions;
    }
    private async Task<LoginResponseViewModel> GerarJwt(IdentityUser user)
    {
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

        claims.AddRange(await _usuarioRepository.ObterClaimsAsync(user));

        var roles = await _usuarioRepository.ObterRolesAsync(user);
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
