using Auth.Domain.Entities;
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
using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Auth.Infra.Identity;
using Auth.Application.Queries.Interfaces;
using NetDevPack.Security.Jwt.Core.Interfaces;

namespace Auth.Application.Services;

public class AuthService : IAuthService
{
    private readonly IAuthRepository _authRepository;
    private readonly INotificador _notificador;
    private readonly JwtSettings _jwtSettings;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IMessageBus _messageBus;
    private readonly string _frontUrl;
    private readonly IAuthQueryService _authQuery;
    private readonly IJwtService _jwksService;

    public AuthService(
        IAuthRepository authRepository,
        INotificador notificador,
        IOptions<JwtSettings> jwtSettings,
        IOptions<RabbitSettings> rabbitSettings,
        SignInManager<ApplicationUser> signInManager,
        IMessageBus messageBus,
        IOptions<FrontEndSettings> settings,
        IJwtService jwksService,
        IAuthQueryService authQuery)
    {
        _jwksService = jwksService;
        _authRepository = authRepository;
        _notificador = notificador;
        _jwtSettings = jwtSettings.Value;
        _signInManager = signInManager;
        _messageBus = messageBus;
        _frontUrl = settings.Value.AllowedApps.First();
        _authQuery = authQuery;
    }

    public async Task<AuthUserViewModel> ObterUsuarioPorId(string id)
    {
        return await _authQuery.ObterUsuarioPorId(id);

        //var usuario = await _authRepository.ObterUsuarioPorIdAsync(id);
        //if(usuario == null)
        //{
        //    _notificador.Handle(new Notificacao("Usuário não encontrado!"));
        //    return default;
        //}
        //var roles = await _authRepository.ObterNomeDasRolesPorUsuarioAsync(usuario);
        //var sistemas = await _systemService.ObterSistemasPorRoleNameAsync(roles);


        //return new AuthUserViewModel
        //{
        //    Email = usuario.Email,
        //    Nome = usuario.Nome,
        //    Systems = sistemas.ToList()
        //};
    }

    public async Task<IEnumerable<AuthUserViewModel>> ListarAuthUser()
    {
        var usuarios = await _authRepository.ObterTodosAuthUserAsync();
        var authUser = new List<AuthUserViewModel>();

        foreach (var user in usuarios)
        {
            authUser.Add(new AuthUserViewModel
            {
                Id = user.Id,
                Email = user.Email,
                Nome = user.Nome,
            });
        }

        return authUser;
    }

    public async Task<bool> AdicionarUsuarioAsync(RegisterUserViewModel registerUser)
    {
        var usuarioExistente = 
            await _authRepository.ObterUsuarioPorEmailAsync(registerUser.Email);

        ApplicationUser user;

        if (usuarioExistente == null)
        {
            user = new ApplicationUser
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

        if (!await SalvaUserRoles(user, registerUser.Profile))
            return false;

        return true;
    }
    

    public async Task<LoginResponseViewModel?> LogarUsuarioAsync(
        LoginUserViewModel loginUser, 
        string scheme, string host
        )
    {
        var user = await _authRepository.ObterUsuarioPorEmailAsync(loginUser.Email);
        if (user == null)
        {
            _notificador.Handle(new Notificacao("usuário ou senha incorretos!"));
            return null;
        };

        var resultCorrectPass = await _signInManager.PasswordSignInAsync(user.UserName, loginUser.Password, false, true);
        if (!resultCorrectPass.Succeeded)
        {
            _notificador.Handle(new Notificacao("usuário ou senha incorretos!"));
            return null;
        }

        var claims = await GerarListaDeClaimsPorUserRole(user);
        if (!await UsuarioTemPermissao(user, loginUser.System.ToUpper(), claims))
            return null;

        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));

        await _signInManager.SignInAsync(user, false);

        var token = await GerarTokenAsync(claims, scheme, host);

        return MontarLoginResponse(user, token, claims);
    }

    public async Task<bool> GerarTokenResetarSenha(ForgotPassViewModel data)
    {
        var user = await _authRepository.ObterUsuarioPorEmailAsync(data.Email);
        if (user == null) return true;

        var confirmado = await _authRepository.isEmailConfirmed(user);
        if (!confirmado) return true;

        var token = await _authRepository.GeraTokenReset(user);

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
        var user = await _authRepository.ObterUsuarioPorEmailAsync(data.Email);
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
        var result = await _authRepository.ResetarSenha(user, data.Token, data.Password);
        if (!result.Succeeded)
        {
            _notificador.Handle(new Notificacao("Houve um erro atualizando a senha!"));
            return false;
        }
        return true;
    }

    private async Task<IList<Claim>> GerarListaDeClaimsPorUserRole(ApplicationUser user)
    {
        var userRoles = await _authRepository.ObterNomeDasRolesPorUsuarioAsync(user);
        var roleClaims = new List<Claim>();

        foreach (var roleName in userRoles)
        {
            var role = await _authRepository.ObterRolePorNomeAsync(roleName);
            if (role == null) continue;

            var claims = await _authRepository.ObterClaimsRoleAsync(role);
            roleClaims.AddRange(claims);
        }

        return roleClaims;
    }

    private async Task<bool> UsuarioTemPermissao(ApplicationUser user, string system, IList<Claim> claims)
    {
        var hasPermission = claims.Any(c =>
            c.Type == "permission" &&
            c.Value.StartsWith(system)
            );

        if (!hasPermission)
        {
            _notificador.Handle(new Notificacao("Usuário não tem permissão nesse sistema!"));
            return false;
        }

        return true;
    }

    private async Task<ResponseMessage> RegistraUsuario(RegisterUserViewModel registerUser)
    {
        var usuario = await _authRepository.ObterUsuarioPorEmailAsync(registerUser.Email);

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
        }
        catch
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

    private async Task<bool> CriaUserIdentity(ApplicationUser user, string password, RegisterUserViewModel registerUser)
    {
        var result = await _authRepository.AdicionarUsuarioAsync(user, password);

        if (!result.Succeeded)
        {
            _notificador.Handle(new Notificacao("Falha ao registrar o usuário"));
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

    private async Task<bool> SalvaUserRoles(ApplicationUser user, string role)
    {
        var userRoles = await _authRepository.ObterNomeDasRolesPorUsuarioAsync(user);
        if (userRoles.Contains(role))
        {
            _notificador.Handle(new Notificacao("O usuário ja tem esse perfil!"));
            return false;
        }

        var resultAddRole = await _authRepository.SalvaRoleAsync(user, role);
        if (!resultAddRole.Succeeded)
        {
            _notificador.Handle(new Notificacao("Falha ao salvar o perfil!"));
            return false;
        }
        return true;
    }

    private async Task<string> GerarTokenAsync(IEnumerable<Claim> claims, string scheme, string host)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = await _jwksService.GetCurrentSigningCredentials();

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = $"{scheme}://{host}",
            Expires = DateTime.UtcNow.AddHours(_jwtSettings.ExpiracaoHoras),
            SigningCredentials = key
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private LoginResponseViewModel MontarLoginResponse(ApplicationUser user, string token, IEnumerable<Claim> claims)
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
