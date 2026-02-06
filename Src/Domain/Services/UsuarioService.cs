using auth.Domain.Entities;
using auth.Domain.Interfaces;
using auth.DTOs;
using auth.Infra.Identity;
using auth.Infra.MessageBus;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace auth.Domain.Services;

public class UsuarioService : IUsuarioService
{
    private readonly IUsuarioRepository _usuarioRepository;
    private readonly INotificador _notificador;
    private readonly JwtSettings _jwtSettings;
    private readonly PermissionModel _permissions;
    private readonly IMessageBus _messageBus;
    private readonly string _frontUrl;

    public UsuarioService(
        IUsuarioRepository usuarioRepository, 
        INotificador notificador,
        IOptions<JwtSettings> jwtSettings,
        PermissionModel permissions,
        IMessageBus messageBus,
        IOptions<FrontEndSettings> settings
        )
    {
        _permissions = permissions;
        _usuarioRepository = usuarioRepository;
        _notificador = notificador;
        _jwtSettings = jwtSettings.Value;
        _messageBus = messageBus;
        _frontUrl = settings.Value.AllowedApps.First();
    }

    public async Task<LoginResponseViewModel?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser)
    {
        var user = new IdentityUser
        {
            UserName = registerUser.Nome + "-" + Guid.NewGuid().ToString(),
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        var usuarioPorEmail = await _usuarioRepository.ObterUsuarioPorEmailAsync(registerUser.Email);

        if (usuarioPorEmail == null)
        {
            var result = await _usuarioRepository.AdicionarUsuarioAsync(user, registerUser.Password);   

            if (!result.Succeeded)
            {
                _notificador.Handle(new Notificacao("Falha ao registrar o usuário"));
                return null;
            }

            if (!await SalvaUserClaims(user, registerUser)) return null;

            await _usuarioRepository.LogarAsync(user);
            return await GerarJwt(user);
        }

        var executaLogin =
            await _usuarioRepository.LogarComSenha(usuarioPorEmail.UserName, registerUser.Password);
        if (!executaLogin.Succeeded)
        {
            _notificador.Handle(new Notificacao("A senha deve ser a mesma do outro sistema para a liberação de permissão!"));
            return null;
        }

        if (!await SalvaUserClaims(usuarioPorEmail, registerUser)) return null;

        await _usuarioRepository.LogarAsync(usuarioPorEmail);
        return await GerarJwt(usuarioPorEmail);
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

        var result = await _usuarioRepository.LogarComSenha(user.UserName, loginUser.Password);
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

        await _usuarioRepository.LogarAsync(user);
        return await GerarJwt(user);
    }

    public async Task<string> GerarTokenResetSenha(string email)
    {
        var genericMsg = "Verifique o email para prosseguir";
        var user = await _usuarioRepository.ObterUsuarioPorEmailAsync(email);
        if (user == null) return genericMsg;

        var confirmado = await _usuarioRepository.isEmailConfirmed(user);
        if (!confirmado) return genericMsg;

        var token = await _usuarioRepository.GeraTokenReset(user);

        var encodedEmail = Uri.EscapeDataString(email);
        var encodedToken = Uri.EscapeDataString(token);

        var resetLink = $"{_frontUrl}/reset-password?email={encodedEmail}&token={encodedToken}";

        await _messageBus.PublishAsync(geraEmailEvent(email, resetLink, user.Id), "email.send");
        return genericMsg;
    }

    public EmailEvent geraEmailEvent(string email, string resetLink, string userId)
        => new EmailEvent
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

    public async Task<bool> ResetarSenha(string email, string token, string password)
    {
        var decodedEmail = Uri.UnescapeDataString(email);
        if (string.IsNullOrWhiteSpace(decodedEmail)) 
        {
            _notificador.Handle(new Notificacao("Email inválido"));
            return false;
        }

        var decodedToken = Uri.UnescapeDataString(token);
        if (string.IsNullOrWhiteSpace(decodedToken))
        {
            _notificador.Handle(new Notificacao("Token inválido"));
            return false;
        }

        if(string.IsNullOrWhiteSpace(password))
        {
            _notificador.Handle(new Notificacao("Senha inválida"));
            return false;
        }

        var user = await _usuarioRepository.ObterUsuarioPorEmailAsync(decodedEmail);
        if (user == null) 
        {
            _notificador.Handle(new Notificacao("Falha ao atualizar a senha"));
            return false;
        }
        
        var result = await _usuarioRepository.ResetSenha(user, decodedToken, password);
        if (!result.Succeeded)
        {
            _notificador.Handle(new Notificacao("Falha ao atualizar a senha"));
            return false;
        }
        return true;

    }
}
