using Auth.Application.Queries.Interfaces;
using Auth.Domain.Entities;
using Auth.Domain.Extensions;
using Auth.Domain.Models;
using Auth.Domain.ViewModel;
using Auth.Infra.Identity;
using Auth.Infra.Interfaces;
using Bus;
using FluentValidation.Results;
using Messages;
using Messages.Integration;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FV = FluentValidation.Results;

namespace Auth.Application.Services;

/// <summary>
/// Serviço de aplicação para gestão de autenticação, usuários e integração de identidade.
/// </summary>
public class AuthService : BaseService, IAuthService
{
    private readonly IAuthRepository _authRepository;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IMessageBus _messageBus;
    private readonly string _frontUrl;
    private readonly IAuthQueryService _authQuery;
    private readonly IJwtService _jwksService;
    private readonly AppTokenSettings _appTokenSettings;

    public AuthService(
        IAuthRepository authRepository,
        INotificador notificador,
        IOptions<RabbitSettings> rabbitSettings,
        SignInManager<ApplicationUser> signInManager,
        IMessageBus messageBus,
        IOptions<FrontEndSettings> settings,
        IJwtService jwksService,
        IOptions<AppTokenSettings> appTokenSettings,
        IAuthQueryService authQuery) : base(notificador)
    {
        _appTokenSettings = appTokenSettings.Value;
        _jwksService = jwksService;
        _authRepository = authRepository;
        _signInManager = signInManager;
        _messageBus = messageBus;
        _frontUrl = settings.Value.AllowedApps.First();
        _authQuery = authQuery;
    }

    public async Task<AuthUserViewModel?> ObterUsuarioPorId(string id)
    {
        return await _authQuery.ObterUsuarioPorId(id);
    }

    public async Task<IEnumerable<AuthUserViewModel>> ListarAuthUser()
    {
        return await _authQuery.ObterUsuariosComSistemas();
    }

    public async Task<string?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser)
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
                EmailConfirmed = true,
                Nome = registerUser.Nome
            };
            var created = await CriaUserIdentity(user, registerUser.Password, registerUser);
            if (!created) return default;
        } else
        {
            if (string.IsNullOrWhiteSpace(usuarioExistente.UserName))
                return RetornaErroProcessamento<string?>("O Nome de usuário não pode ser nulo");

            var executaLogin =
                await _signInManager.PasswordSignInAsync(usuarioExistente.UserName, registerUser.Password, false, true);

            if (!executaLogin.Succeeded)
                return RetornaErroProcessamento<string?>("A senha deve ser a mesma do outro sistema para a liberação de permissão!");

            user = usuarioExistente;
        }

        var usuarioRegistrado = await RegistraUsuario(registerUser);

        if (!usuarioRegistrado.ValidationResult.IsValid || usuarioRegistrado == null)
            return default;

        if (!await SalvaUserRoles(user, registerUser.Profile))
            return default;

        return user.Id;
    }
    

    public async Task<LoginResponseViewModel?> LogarUsuarioAsync(
        LoginUserViewModel loginUser, 
        string scheme, string host
        )
    {
        var user = await ExecuteAsync(async () => await _authRepository.ObterUsuarioPorEmailAsync(loginUser.Email));
        if (user == null || string.IsNullOrWhiteSpace(user.UserName))
            return RetornaErroProcessamento<LoginResponseViewModel?>("usuário ou senha incorretos!");

        var resultCorrectPass = await ExecuteAsync(async () => 
            await _signInManager.PasswordSignInAsync(user.UserName, loginUser.Password, false, true));
        if (resultCorrectPass is null || !resultCorrectPass.Succeeded)
            return RetornaErroProcessamento<LoginResponseViewModel?>("usuário ou senha incorretos!");

        await ExecuteAsync(async () => 
            await _signInManager.SignInAsync(user, false));

        var claims = await MountUserClaims(user, loginUser.System);
        var token = await GenerateJwt(loginUser.Email, loginUser.System, scheme, host, user, claims);
        var refreshToken = await GenerateRefreshToken(loginUser.Email);

        if (string.IsNullOrEmpty(token) || claims is null || string.IsNullOrEmpty(refreshToken))
            return default;

        return MontarLoginResponse(user, token, claims, refreshToken);
    }


    // Pode ser otimizado
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

        await _messageBus.PublishAsync(GeraEmailEvent(data.Email, resetLink, user.Id));
        return true;
    }

    public async Task<bool> RecuperarSenha(ResetPassViewModel data)
    {
        if (string.IsNullOrEmpty(data.Email))
            return RetornaErroProcessamento<bool>("Email inválido!");

        var user = await _authRepository.ObterUsuarioPorEmailAsync(data.Email);
        if (user == null)
            return RetornaErroProcessamento<bool>("Usuário não encontrado!");

        if (string.IsNullOrEmpty(data.Password) || string.IsNullOrEmpty(data.Token))
            return RetornaErroProcessamento<bool>("token inválido");

        var result = await _authRepository.ResetarSenha(user, data.Token, data.Password);
        if (!result.Succeeded)
            return RetornaErroProcessamento<bool>("Houve um erro atualizando a senha!");

        return true;
    }

    public async Task<string?> RefreshToken(RefreshTokenRequestViewModel request, string scheme, string host)
    {
        Guid parsedToken;
        if (string.IsNullOrEmpty(request.RefreshToken) || 
            string.IsNullOrEmpty(request.System) || 
            !Guid.TryParse(request.RefreshToken, out parsedToken))
            return RetornaErroProcessamento<string>("Refresh token inválido");


        var tokenPersisted = await ExecuteAsync(async () => await _authRepository.getRefreshToken(parsedToken));

        if (tokenPersisted is null)
            return RetornaErroProcessamento<string>("Refresh Token expirado");

        var token = await GenerateJwt(tokenPersisted.UserName, request.System, scheme, host);
        if (string.IsNullOrEmpty(token))
            return default;

        return token;
    }

    private async Task<IList<Claim>?> MountUserClaims(ApplicationUser user, string system)
    {
        var claims = await GerarListaDeClaimsPorUserRole(user);
        if (!await UsuarioTemPermissao(user, system.ToUpper(), claims))
            return default;

        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
        return claims;
    }


    private async Task<string?> GenerateJwt(
        string email,
        string system,
        string scheme,
        string host,
        ApplicationUser? user = null,
        IList<Claim>? claims = null)
    {
        user ??= await ExecuteAsync(
                async () => await _authRepository.ObterUsuarioPorEmailAsync(email));
        if (user is null)
            return RetornaErroProcessamento<string>("Usuario não encontrado!");

        claims ??= await MountUserClaims(user, system);
        if (claims is null)
            return RetornaErroProcessamento<string>("Falha ao buscar as claims para gerar o jwt");

        return await GerarTokenAsync(claims, scheme, host);
    }

    private async Task<string?> GenerateRefreshToken(string email)
    {
        var refreshToken = new RefreshToken
        {
            UserName = email,
            ExpirationDate = DateTime.UtcNow.AddDays(_appTokenSettings.RefreshTokenExpiration)
        };
        var result = await _authRepository.updateRefreshToken(refreshToken);
        if (!result)
            return RetornaErroProcessamento<string>("Erro atualizando refresh token");
        return refreshToken.Token.ToString();

    }

    // Da pra otimizar
    private async Task<IList<Claim>> GerarListaDeClaimsPorUserRole(ApplicationUser user)
    {
        var userRoles = await ExecuteAsync(async () => await _authRepository.ObterNomeDasRolesPorUsuarioAsync(user));
        var roleClaims = new List<Claim>();

        foreach (var roleName in userRoles ?? new List<string>())
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
            return RetornaErroProcessamento<bool>("Usuário não tem permissão nesse sistema!");

        return true;
    }

    private async Task<ResponseMessage> RegistraUsuario(RegisterUserViewModel registerUser)
    {
        var usuario = await _authRepository.ObterUsuarioPorEmailAsync(registerUser.Email);

        if (usuario == null)
        {
            _notificador.Handle("Usuario não encontrado!");
            return new ResponseMessage(
                new ValidationResult(
                        [
                            new FV.ValidationFailure("", "Usuario não encontrado!")
                        ]
                    ));
        }

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
                    _notificador.Handle(error.ErrorMessage);

                return usuarioResult;
            }

            return usuarioResult;
        }
        catch
        {
            _notificador.Handle("Erro ao cadastrar usuário no sistema");
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
            return RetornaErroProcessamento<bool>("Falha ao registrar o usuário!");

        return true;
    }

    private EmailIntegrationEvent GeraEmailEvent(string email, string resetLink, string userId)
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
            return RetornaErroProcessamento<bool>("O usuário ja tem esse perfil!");

        var resultAddRole = await _authRepository.SalvaRoleAsync(user, role);
        if (!resultAddRole.Succeeded)
            return RetornaErroProcessamento<bool>("Falha ao salvar o perfil!");

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
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = key
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private LoginResponseViewModel MontarLoginResponse(ApplicationUser user, string token, IEnumerable<Claim> claims, string refreshToken)
    {
        return new LoginResponseViewModel
        {
            AccessToken = token,
            RefreshToken = refreshToken,
            ExpiresIn = TimeSpan
                .FromHours(1)
                .TotalSeconds,
            UserToken = new UserTokenViewModel
            {
                Id = user.Id,
                Name = user.UserName ?? "",
                Claims = claims.Select(c => new ClaimViewModel
                {
                    Type = c.Type,
                    Value = c.Value
                }).ToList()
            }
        };
    }

    public async Task<bool> RemoverUsuarioAsync(string id)
    {
        var usuario = await _authRepository.ObterUsuarioPorIdAsync(id);
        if(usuario is null)
            return RetornaErroProcessamento<bool>("Usuario não encontrado!");

        var result = await _authRepository.DeleteAsync(usuario);
        if (result.Succeeded)
            return true;

        return RetornaErroProcessamento<bool>("Houve um erro ao excluir o usuário!");
    }
}
