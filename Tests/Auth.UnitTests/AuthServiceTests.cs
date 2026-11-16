using System.Security.Claims;
using System.Security.Cryptography;
using Auth.Application.Queries.Interfaces;
using Auth.Application.Services;
using Auth.Domain.Entities;
using Auth.Domain.Exceptions;
using Auth.Domain.Extensions;
using Auth.Domain.Models;
using Auth.Domain.ViewModel;
using Auth.Infra.Identity;
using Auth.Infra.Interfaces;
using Auth.Infra.Notifications;
using Bus;
using FluentValidation.Results;
using Messages;
using Messages.Integration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NetDevPack.Security.Jwt.Core.Interfaces;
using Xunit;

namespace Auth.UnitTests;

public class AuthServiceTests
{
    private readonly Mock<IAuthRepository> _authRepositoryMock = new();
    private readonly Notificador _notificador = new();
    private readonly Mock<SignInManager<ApplicationUser>> _signInManagerMock;
    private readonly Mock<IMessageBus> _messageBusMock = new();
    private readonly Mock<IJwtService> _jwksServiceMock = new();
    private readonly Mock<IAuthQueryService> _authQueryMock = new();
    private readonly IConfiguration _configuration;
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
        var userManagerMock = new Mock<UserManager<ApplicationUser>>(
            userStoreMock.Object,
            null!, null!, null!, null!, null!, null!, null!, null!);

        _signInManagerMock = new Mock<SignInManager<ApplicationUser>>(
            userManagerMock.Object,
            new Mock<IHttpContextAccessor>().Object,
            new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>().Object,
            new Mock<IOptions<IdentityOptions>>().Object,
            new Mock<ILogger<SignInManager<ApplicationUser>>>().Object,
            new Mock<IAuthenticationSchemeProvider>().Object,
            new Mock<IUserConfirmation<ApplicationUser>>().Object);

        var rsaKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = Guid.NewGuid().ToString() };
        var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);
        _jwksServiceMock
            .Setup(x => x.GetCurrentSigningCredentials())
            .ReturnsAsync(signingCredentials);

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["JwtSettings:Issuer"] = "http://localhost:8080"
            })
            .Build();

        _sut = new AuthService(
            _authRepositoryMock.Object,
            _notificador,
            Options.Create(new RabbitSettings()),
            _signInManagerMock.Object,
            _messageBusMock.Object,
            Options.Create(new FrontEndSettings { AllowedApps = ["http://localhost:5071"] }),
            _jwksServiceMock.Object,
            Options.Create(new AppTokenSettings { RefreshTokenExpiration = 7 }),
            _authQueryMock.Object,
            _configuration);
    }

    // ── Consultas ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ObterUsuarioPorId_DeveDelegarParaAuthQueryService()
    {
        var expected = new AuthUserViewModel { Id = "u1", Nome = "User", Email = "u@teste.com", Systems = [] };
        _authQueryMock.Setup(x => x.ObterUsuarioPorId("u1")).ReturnsAsync(expected);

        var result = await _sut.ObterUsuarioPorId("u1");

        Assert.Same(expected, result);
    }

    [Fact]
    public async Task ListarAuthUser_DeveDelegarParaAuthQueryService()
    {
        var list = new List<AuthUserViewModel>
        {
            new() { Id = "u1", Nome = "User", Email = "u@teste.com", Systems = [] }
        };
        _authQueryMock.Setup(x => x.ObterUsuariosComSistemas()).ReturnsAsync(list);

        var result = await _sut.ListarAuthUser();

        Assert.Single(result);
    }

    // ── Login ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LogarUsuarioAsync_UsuarioNaoEncontrado_DeveRetornarNuloENotificarErro()
    {
        _authRepositoryMock
            .Setup(x => x.ObterUsuarioPorEmailAsync("inexistente@teste.com"))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _sut.LogarUsuarioAsync(new LoginUserViewModel
        {
            Email = "inexistente@teste.com",
            Password = "Password123!",
            System = "AUTH"
        }, "http", "localhost:8080");

        Assert.Null(result);
        Assert.True(_notificador.TemNotificacao());
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("usuário ou senha incorretos"));
    }

    [Fact]
    public async Task LogarUsuarioAsync_SenhaIncorretaOuLockout_DeveRetornarNuloENotificarErro()
    {
        var user = new ApplicationUser { Id = "u1", UserName = "user@teste.com", Email = "user@teste.com", Nome = "User" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "SenhaErrada", true))
            .ReturnsAsync(SignInResult.LockedOut);

        var result = await _sut.LogarUsuarioAsync(new LoginUserViewModel
        {
            Email = user.Email,
            Password = "SenhaErrada",
            System = "AUTH"
        }, "http", "localhost:8080");

        Assert.Null(result);
        Assert.True(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task LogarUsuarioAsync_SistemaInexistente_DeveRetornarNuloENotificarSistemaNaoEncontrado()
    {
        var user = new ApplicationUser { Id = "u1", UserName = "user@teste.com", Email = "user@teste.com", Nome = "User" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "Senha123!", true))
            .ReturnsAsync(SignInResult.Success);
        _authRepositoryMock.Setup(x => x.ObterClaimsPorUsuarioAsync(user)).ReturnsAsync([]);
        _authRepositoryMock.Setup(x => x.SistemaExisteAsync("INEXISTENTE")).ReturnsAsync(false);

        var result = await _sut.LogarUsuarioAsync(new LoginUserViewModel
        {
            Email = user.Email,
            Password = "Senha123!",
            System = "INEXISTENTE"
        }, "http", "localhost:8080");

        Assert.Null(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("Sistema não encontrado"));
    }

    [Fact]
    public async Task LogarUsuarioAsync_PrefixoDeOutroSistema_DeveBloquearFalsoPositivo()
    {
        var user = new ApplicationUser { Id = "u1", UserName = "user@teste.com", Email = "user@teste.com", Nome = "User" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "Senha123!", true))
            .ReturnsAsync(SignInResult.Success);
        _authRepositoryMock.Setup(x => x.SistemaExisteAsync("FIN")).ReturnsAsync(true);
        _authRepositoryMock
            .Setup(x => x.ObterClaimsPorUsuarioAsync(user))
            .ReturnsAsync([new Claim("permission", "FINANCEIRO:LER")]);

        var result = await _sut.LogarUsuarioAsync(new LoginUserViewModel
        {
            Email = user.Email,
            Password = "Senha123!",
            System = "FIN"
        }, "http", "localhost:8080");

        Assert.Null(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("permissão nesse sistema"));
    }

    [Fact]
    public async Task LogarUsuarioAsync_CredenciaisEPermissaoValidas_DeveGerarJwtERefreshTokenSemConsultarSistemaNoBanco()
    {
        var user = new ApplicationUser { Id = "u1", UserName = "admin@teste.com", Email = "admin@teste.com", Nome = "Admin" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "Senha123!", true))
            .ReturnsAsync(SignInResult.Success);
        _authRepositoryMock
            .Setup(x => x.ObterClaimsPorUsuarioAsync(user))
            .ReturnsAsync([new Claim("permission", "AUTH:LER")]);
        _authRepositoryMock
            .Setup(x => x.updateRefreshToken(It.IsAny<RefreshToken>()))
            .ReturnsAsync(true);

        var result = await _sut.LogarUsuarioAsync(new LoginUserViewModel
        {
            Email = user.Email,
            Password = "Senha123!",
            System = "AUTH"
        }, "http", "localhost:8080");

        Assert.NotNull(result);
        Assert.False(string.IsNullOrWhiteSpace(result.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(result.RefreshToken));
        Assert.Equal("u1", result.UserToken.Id);
        Assert.False(_notificador.TemNotificacao());
        _authRepositoryMock.Verify(x => x.SistemaExisteAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task LogarUsuarioAsync_ExcecaoDeBanco_DeveCapturarEmBaseServiceENotificar()
    {
        _authRepositoryMock
            .Setup(x => x.ObterUsuarioPorEmailAsync(It.IsAny<string>()))
            .ThrowsAsync(new DatabaseException("Timeout no Postgres"));

        var result = await _sut.LogarUsuarioAsync(new LoginUserViewModel
        {
            Email = "admin@teste.com",
            Password = "Senha123!",
            System = "AUTH"
        }, "http", "localhost:8080");

        Assert.Null(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("Erro no banco: Timeout no Postgres"));
    }

    // ── Refresh Token ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("", "AUTH")]
    [InlineData("nao-eh-guid", "AUTH")]
    [InlineData("d32bda50-24bc-4232-b2fe-578bf56a3ecc", "")]
    public async Task RefreshToken_ParametrosInvalidos_DeveRetornarNuloENotificar(string token, string system)
    {
        var result = await _sut.RefreshToken(new RefreshTokenRequestViewModel
        {
            RefreshToken = token,
            System = system
        }, "http", "localhost:8080");

        Assert.Null(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("Refresh token inválido"));
    }

    [Fact]
    public async Task RefreshToken_TokenExpirado_DeveRetornarNuloENotificarExpirado()
    {
        var expiredToken = new RefreshToken
        {
            UserName = "admin@teste.com",
            ExpirationDate = DateTime.UtcNow.AddMinutes(-5)
        };

        _authRepositoryMock
            .Setup(x => x.getRefreshToken(expiredToken.Token))
            .ReturnsAsync(expiredToken);

        var result = await _sut.RefreshToken(new RefreshTokenRequestViewModel
        {
            RefreshToken = expiredToken.Token.ToString(),
            System = "AUTH"
        }, "http", "localhost:8080");

        Assert.Null(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("Refresh Token expirado"));
    }

    [Fact]
    public async Task RefreshToken_TokenValido_DeveGerarNovoJwtERotacionarRefreshToken()
    {
        var validToken = new RefreshToken
        {
            UserName = "admin@teste.com",
            ExpirationDate = DateTime.UtcNow.AddDays(3)
        };
        var user = new ApplicationUser { Id = "u1", UserName = "admin@teste.com", Email = "admin@teste.com", Nome = "Admin" };

        _authRepositoryMock.Setup(x => x.getRefreshToken(validToken.Token)).ReturnsAsync(validToken);
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _authRepositoryMock.Setup(x => x.SistemaExisteAsync("AUTH")).ReturnsAsync(true);
        _authRepositoryMock.Setup(x => x.ObterClaimsPorUsuarioAsync(user)).ReturnsAsync([new Claim("permission", "AUTH:LER")]);
        _authRepositoryMock.Setup(x => x.updateRefreshToken(It.IsAny<RefreshToken>())).ReturnsAsync(true);

        var result = await _sut.RefreshToken(new RefreshTokenRequestViewModel
        {
            RefreshToken = validToken.Token.ToString(),
            System = "AUTH"
        }, "http", "localhost:8080");

        Assert.NotNull(result);
        Assert.NotEqual(validToken.Token.ToString(), result.RefreshToken);
        _authRepositoryMock.Verify(x => x.updateRefreshToken(It.IsAny<RefreshToken>()), Times.Once);
    }

    // ── Registro de Usuário ──────────────────────────────────────────────────

    [Fact]
    public async Task AdicionarUsuarioAsync_RoleInexistenteNoSistema_DeveRetornarNuloSemCriarUsuario()
    {
        _authRepositoryMock
            .Setup(x => x.ObterRolePorSistemaENomeAsync("FIN", "Inexistente"))
            .ReturnsAsync((ApplicationRole?)null);

        var userId = await _sut.AdicionarUsuarioAsync(new RegisterUserViewModel
        {
            Nome = "Teste",
            Email = "t@teste.com",
            Password = "Senha123!",
            ConfirmPassword = "Senha123!",
            System = "FIN",
            Profile = "Inexistente"
        });

        Assert.Null(userId);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("Perfil não encontrado"));
        _authRepositoryMock.Verify(x => x.AdicionarUsuarioAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task AdicionarUsuarioAsync_NovoUsuarioSistemaAuth_DeveCriarEVincularRoleSemChamarRabbitMq()
    {
        var role = new ApplicationRole { Id = "role-auth-admin", Name = "Admin", SystemId = "sys-auth" };
        _authRepositoryMock
            .Setup(x => x.ObterRolePorSistemaENomeAsync("AUTH", "Admin"))
            .ReturnsAsync(role);
        _authRepositoryMock
            .Setup(x => x.ObterUsuarioPorEmailAsync("novo@teste.com"))
            .ReturnsAsync((ApplicationUser?)null);
        _authRepositoryMock
            .Setup(x => x.AdicionarUsuarioAsync(It.IsAny<ApplicationUser>(), "Senha123!"))
            .ReturnsAsync(IdentityResult.Success);
        _authRepositoryMock
            .Setup(x => x.UsuarioPossuiRolePorIdAsync(It.IsAny<string>(), role.Id))
            .ReturnsAsync(false);
        _authRepositoryMock
            .Setup(x => x.SalvaUserRolePorIdAsync(It.IsAny<string>(), role.Id))
            .ReturnsAsync(true);

        var userId = await _sut.AdicionarUsuarioAsync(new RegisterUserViewModel
        {
            Nome = "Novo Admin",
            Email = "novo@teste.com",
            Password = "Senha123!",
            ConfirmPassword = "Senha123!",
            System = "AUTH",
            Profile = "Admin"
        });

        Assert.False(string.IsNullOrWhiteSpace(userId));
        _messageBusMock.Verify(
            x => x.RequestAsync<UsuarioRegistradoIntegrationEvent, ResponseMessage>(It.IsAny<UsuarioRegistradoIntegrationEvent>()),
            Times.Never);
    }

    [Fact]
    public async Task AdicionarUsuarioAsync_UsuarioExistenteSenhaDiferente_DeveBloquearVinculo()
    {
        var role = new ApplicationRole { Id = "role-fin", Name = "Admin", SystemId = "sys-fin" };
        var existing = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };

        _authRepositoryMock.Setup(x => x.ObterRolePorSistemaENomeAsync("FIN", "Admin")).ReturnsAsync(role);
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync("u@teste.com")).ReturnsAsync(existing);
        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(existing, "SenhaErrada", true))
            .ReturnsAsync(SignInResult.Failed);

        var userId = await _sut.AdicionarUsuarioAsync(new RegisterUserViewModel
        {
            Nome = "User",
            Email = "u@teste.com",
            Password = "SenhaErrada",
            ConfirmPassword = "SenhaErrada",
            System = "FIN",
            Profile = "Admin"
        });

        Assert.Null(userId);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("A senha deve ser a mesma"));
    }

    [Fact]
    public async Task AdicionarUsuarioAsync_UsuarioExistenteJaPossuiRole_DeveBloquearAntesDoRabbitMq()
    {
        var role = new ApplicationRole { Id = "role-fin", Name = "Admin", SystemId = "sys-fin" };
        var existing = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };

        _authRepositoryMock.Setup(x => x.ObterRolePorSistemaENomeAsync("FIN", "Admin")).ReturnsAsync(role);
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync("u@teste.com")).ReturnsAsync(existing);
        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(existing, "Senha123!", true))
            .ReturnsAsync(SignInResult.Success);
        _authRepositoryMock.Setup(x => x.UsuarioPossuiRolePorIdAsync("u1", "role-fin")).ReturnsAsync(true);

        var userId = await _sut.AdicionarUsuarioAsync(new RegisterUserViewModel
        {
            Nome = "User",
            Email = "u@teste.com",
            Password = "Senha123!",
            ConfirmPassword = "Senha123!",
            System = "FIN",
            Profile = "Admin"
        });

        Assert.Null(userId);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("ja tem esse perfil"));
        _messageBusMock.Verify(
            x => x.RequestAsync<UsuarioRegistradoIntegrationEvent, ResponseMessage>(It.IsAny<UsuarioRegistradoIntegrationEvent>()),
            Times.Never);
    }

    [Fact]
    public async Task AdicionarUsuarioAsync_FalhaRabbitMqEmNovoUsuario_DeveExecutarRollback()
    {
        var role = new ApplicationRole { Id = "role-fin-user", Name = "Basico", SystemId = "sys-fin" };
        var createdUser = new ApplicationUser { Id = "u-new", Email = "fin@teste.com", UserName = "fin@teste.com", Nome = "Fin" };

        _authRepositoryMock
            .Setup(x => x.ObterRolePorSistemaENomeAsync("FIN", "Basico"))
            .ReturnsAsync(role);
        _authRepositoryMock
            .SetupSequence(x => x.ObterUsuarioPorEmailAsync("fin@teste.com"))
            .ReturnsAsync((ApplicationUser?)null)
            .ReturnsAsync(createdUser);
        _authRepositoryMock
            .Setup(x => x.AdicionarUsuarioAsync(It.IsAny<ApplicationUser>(), "Senha123!"))
            .ReturnsAsync(IdentityResult.Success);
        _authRepositoryMock
            .Setup(x => x.DeleteAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        var invalidValidation = new ValidationResult([new ValidationFailure("Email", "Erro no serviço consumidor")]);
        _messageBusMock
            .Setup(x => x.RequestAsync<UsuarioRegistradoIntegrationEvent, ResponseMessage>(It.IsAny<UsuarioRegistradoIntegrationEvent>()))
            .ReturnsAsync(new ResponseMessage(invalidValidation));

        var userId = await _sut.AdicionarUsuarioAsync(new RegisterUserViewModel
        {
            Nome = "Fin",
            Email = "fin@teste.com",
            Password = "Senha123!",
            ConfirmPassword = "Senha123!",
            System = "FIN",
            Profile = "Basico"
        });

        Assert.Null(userId);
        _authRepositoryMock.Verify(x => x.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Once);
    }

    // ── Recuperação e Redefinição de Senha ───────────────────────────────────

    [Fact]
    public async Task GerarTokenResetarSenha_UsuarioInexistente_DeveRetornarTrueSilenciosamenteSemPublicarEvento()
    {
        _authRepositoryMock
            .Setup(x => x.ObterUsuarioPorEmailAsync("naoexiste@teste.com"))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await _sut.GerarTokenResetarSenha(new ForgotPassViewModel { Email = "naoexiste@teste.com" });

        Assert.True(result);
        _messageBusMock.Verify(x => x.PublishAsync(It.IsAny<EmailIntegrationEvent>()), Times.Never);
    }

    [Fact]
    public async Task GerarTokenResetarSenha_UsuarioValidoConfirmado_DevePublicarEventoDeEmailNoRabbitMq()
    {
        var user = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _authRepositoryMock.Setup(x => x.isEmailConfirmed(user)).ReturnsAsync(true);
        _authRepositoryMock.Setup(x => x.GeraTokenReset(user)).ReturnsAsync("token+reset/123");

        var result = await _sut.GerarTokenResetarSenha(new ForgotPassViewModel { Email = user.Email });

        Assert.True(result);
        _messageBusMock.Verify(
            x => x.PublishAsync(It.Is<EmailIntegrationEvent>(e =>
                e.To == user.Email &&
                e.Type == "RESET" &&
                e.Body.Contains("http://localhost:5071/auth?email="))),
            Times.Once);
    }

    [Fact]
    public async Task RecuperarSenha_DadosValidos_DeveResetarSenhaERetornarTrue()
    {
        var user = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _authRepositoryMock
            .Setup(x => x.ResetarSenha(user, "tok-123", "NovaSenha123!"))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _sut.RecuperarSenha(new ResetPassViewModel
        {
            Email = user.Email,
            Token = "tok-123",
            Password = "NovaSenha123!"
        });

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task RecuperarSenha_TokenInvalidoNoIdentity_DeveRetornarFalseENotificar()
    {
        var user = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorEmailAsync(user.Email)).ReturnsAsync(user);
        _authRepositoryMock
            .Setup(x => x.ResetarSenha(user, "tok-invalido", "NovaSenha123!"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Invalid token" }));

        var result = await _sut.RecuperarSenha(new ResetPassViewModel
        {
            Email = user.Email,
            Token = "tok-invalido",
            Password = "NovaSenha123!"
        });

        Assert.False(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("erro atualizando a senha"));
    }

    // ── Exclusão de Usuário ──────────────────────────────────────────────────

    [Fact]
    public async Task RemoverUsuarioAsync_UsuarioNaoEncontrado_DeveRetornarFalseENotificar()
    {
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorIdAsync("inexistente")).ReturnsAsync((ApplicationUser?)null);

        var result = await _sut.RemoverUsuarioAsync("inexistente");

        Assert.False(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("Usuario não encontrado"));
    }

    [Fact]
    public async Task RemoverUsuarioAsync_UsuarioExistente_DeveExcluirERetornarTrue()
    {
        var user = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };
        _authRepositoryMock.Setup(x => x.ObterUsuarioPorIdAsync("u1")).ReturnsAsync(user);
        _authRepositoryMock.Setup(x => x.DeleteAsync(user)).ReturnsAsync(IdentityResult.Success);

        var result = await _sut.RemoverUsuarioAsync("u1");

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }
}
