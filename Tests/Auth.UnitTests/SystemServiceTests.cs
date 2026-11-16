using System.Security.Claims;
using Auth.Application.Queries.Interfaces;
using Auth.Application.Services;
using Auth.Domain.Entities;
using Auth.Domain.ViewModel;
using Auth.Infra.Identity;
using Auth.Infra.Interfaces;
using Auth.Infra.Notifications;
using Microsoft.AspNetCore.Identity;
using Moq;
using Xunit;

namespace Auth.UnitTests;

public class SystemServiceTests
{
    private readonly Notificador _notificador = new();
    private readonly Mock<ISystemRepository> _systemRepositoryMock = new();
    private readonly Mock<IAuthRepository> _authRepositoryMock = new();
    private readonly Mock<ISystemQueryService> _systemQueryMock = new();
    private readonly SystemService _sut;

    public SystemServiceTests()
    {
        _sut = new SystemService(
            _notificador,
            _systemRepositoryMock.Object,
            _authRepositoryMock.Object,
            _systemQueryMock.Object);
    }

    [Fact]
    public async Task AdicionaSistemaAsync_DadosInvalidos_DeveRetornarFalseENotificarErros()
    {
        var result = await _sut.AdicionaSistemaAsync(new SystemViewModel
        {
            Id = "",
            Name = "",
            Url = "",
            Permissoes = []
        });

        Assert.False(result);
        Assert.Equal(3, _notificador.ObterNotificacoes().Count);
        _systemRepositoryMock.Verify(x => x.AdicionarAsync(It.IsAny<SystemEntity>()), Times.Never);
    }

    [Fact]
    public async Task AdicionaSistemaAsync_DadosValidos_DeveAdicionarERetornarTrue()
    {
        _systemRepositoryMock
            .Setup(x => x.AdicionarAsync(It.IsAny<SystemEntity>()))
            .ReturnsAsync(true);

        var result = await _sut.AdicionaSistemaAsync(new SystemViewModel
        {
            Id = "sys-1",
            Name = "Financeiro",
            Url = "https://fin.local",
            Permissoes = []
        });

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task AtualizaSistemaAsync_CamposObrigatoriosVazios_DeveRetornarFalseENotificar()
    {
        var result = await _sut.AtualizaSistemaAsync(new SystemViewModel
        {
            Id = "sys-1",
            Name = "",
            Url = "",
            Permissoes = []
        });

        Assert.False(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("obrigatórios"));
    }

    [Fact]
    public async Task AtualizaSistemaAsync_SistemaInexistente_DeveRetornarFalseENotificar()
    {
        _systemRepositoryMock.Setup(x => x.ObterSistemaPorId("inexistente")).ReturnsAsync((SystemEntity?)null);

        var result = await _sut.AtualizaSistemaAsync(new SystemViewModel
        {
            Id = "inexistente",
            Name = "Novo",
            Url = "https://new.local",
            Permissoes = []
        });

        Assert.False(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("Sistema não encontrado"));
    }

    [Fact]
    public async Task AtualizaSistemaAsync_FalhaNoRepositorio_DeveRetornarFalseENotificarErro()
    {
        var existing = new SystemEntity { Id = "sys-1", Name = "Antigo", Url = "https://old.local" };
        _systemRepositoryMock.Setup(x => x.ObterSistemaPorId("sys-1")).ReturnsAsync(existing);
        _systemRepositoryMock.Setup(x => x.AtualizarAsync(existing)).ReturnsAsync(false);

        var result = await _sut.AtualizaSistemaAsync(new SystemViewModel
        {
            Id = "sys-1",
            Name = "Novo",
            Url = "https://new.local",
            Permissoes = []
        });

        Assert.False(result);
        Assert.True(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task AtualizaSistemaAsync_DadosValidos_DeveAtualizarERetornarTrue()
    {
        var existing = new SystemEntity { Id = "sys-1", Name = "Antigo", Url = "https://old.local" };
        _systemRepositoryMock.Setup(x => x.ObterSistemaPorId("sys-1")).ReturnsAsync(existing);
        _systemRepositoryMock.Setup(x => x.AtualizarAsync(existing)).ReturnsAsync(true);

        var result = await _sut.AtualizaSistemaAsync(new SystemViewModel
        {
            Id = "sys-1",
            Name = "Novo Nome",
            Url = "https://new.local",
            Permissoes = []
        });

        Assert.True(result);
        Assert.Equal("Novo Nome", existing.Name);
        Assert.Equal("https://new.local", existing.Url);
    }

    [Fact]
    public async Task RemoveSistemaAsync_SistemaComRolesAssociadas_DeveBloquearExclusao()
    {
        var existing = new SystemEntity { Id = "sys-1", Name = "Auth", Url = "https://auth.local" };
        _systemRepositoryMock.Setup(x => x.ObterSistemaPorId("sys-1")).ReturnsAsync(existing);
        _authRepositoryMock
            .Setup(x => x.ObterRolesPorSistemIdAsync("sys-1"))
            .ReturnsAsync([new ApplicationRole { Id = "r1", Name = "Admin", SystemId = "sys-1" }]);

        var result = await _sut.RemoveSistemaAsync("sys-1");

        Assert.False(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("possui perfis"));
        _systemRepositoryMock.Verify(x => x.RemoverAsync(It.IsAny<SystemEntity>()), Times.Never);
    }

    [Fact]
    public async Task RemoveSistemaAsync_SistemaSemRoles_DeveRemoverERetornarTrue()
    {
        var existing = new SystemEntity { Id = "sys-1", Name = "Auth", Url = "https://auth.local" };
        _systemRepositoryMock.Setup(x => x.ObterSistemaPorId("sys-1")).ReturnsAsync(existing);
        _authRepositoryMock.Setup(x => x.ObterRolesPorSistemIdAsync("sys-1")).ReturnsAsync([]);
        _systemRepositoryMock.Setup(x => x.RemoverAsync(existing)).ReturnsAsync(true);

        var result = await _sut.RemoveSistemaAsync("sys-1");

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task AdicionaRole_DadosValidos_DeveAdicionarERetornarTrue()
    {
        _systemRepositoryMock.Setup(x => x.AdicionaRole(It.IsAny<ApplicationRole>())).ReturnsAsync(true);

        var result = await _sut.AdicionaRole(new ApplicationRoleViewModel
        {
            Id = "r1",
            Name = "Operador",
            SystemId = "sys-1",
            Claims = []
        });

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task RemoverRole_RoleComClaims_DeveBloquearExclusao()
    {
        var role = new ApplicationRole { Id = "r1", Name = "Admin", SystemId = "sys-1" };
        _authRepositoryMock.Setup(x => x.ObterRolePorId("r1")).ReturnsAsync(role);
        _authRepositoryMock
            .Setup(x => x.ObterClaimsRoleAsync(role))
            .ReturnsAsync([new Claim("permission", "AUTH:LER")]);

        var result = await _sut.RemoverRole("r1");

        Assert.False(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("possui claims"));
        _authRepositoryMock.Verify(x => x.RemoverRoleAsync(It.IsAny<ApplicationRole>()), Times.Never);
    }

    [Fact]
    public async Task RemoverRole_RoleSemClaims_DeveExcluirERetornarTrue()
    {
        var role = new ApplicationRole { Id = "r1", Name = "Admin", SystemId = "sys-1" };
        _authRepositoryMock.Setup(x => x.ObterRolePorId("r1")).ReturnsAsync(role);
        _authRepositoryMock.Setup(x => x.ObterClaimsRoleAsync(role)).ReturnsAsync([]);
        _authRepositoryMock.Setup(x => x.RemoverRoleAsync(role)).ReturnsAsync(IdentityResult.Success);

        var result = await _sut.RemoverRole("r1");

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task AdicionaClaim_RoleExistente_DeveConverterParaUpperCaseESalvar()
    {
        var role = new ApplicationRole { Id = "r1", Name = "Admin", SystemId = "sys-1" };
        _authRepositoryMock.Setup(x => x.ObterRolePorId("r1")).ReturnsAsync(role);
        _authRepositoryMock
            .Setup(x => x.SalvaRoleClaim(role, It.Is<Claim>(c => c.Type == "permission" && c.Value == "AUTH:CRIAR")))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _sut.AdicionaClaim(new ApplicationClaimViewModel("r1", "auth:criar"));

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task RemoveClaim_RoleExistente_DeveRemoverERetornarTrue()
    {
        var role = new ApplicationRole { Id = "r1", Name = "Admin", SystemId = "sys-1" };
        _authRepositoryMock.Setup(x => x.ObterRolePorId("r1")).ReturnsAsync(role);
        _authRepositoryMock
            .Setup(x => x.ExcluirRoleClaim(role, It.Is<Claim>(c => c.Type == "permission" && c.Value == "AUTH:CRIAR")))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _sut.RemoveClaim("r1", "AUTH:CRIAR");

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }

    [Fact]
    public async Task VincularUsuarioRoleAsync_UsuarioJaPossuiRole_DeveBloquearENotificar()
    {
        var user = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };
        var role = new ApplicationRole { Id = "r1", Name = "Admin", SystemId = "sys-1" };

        _authRepositoryMock.Setup(x => x.ObterUsuarioPorIdAsync("u1")).ReturnsAsync(user);
        _authRepositoryMock.Setup(x => x.ObterRolePorId("r1")).ReturnsAsync(role);
        _authRepositoryMock.Setup(x => x.UsuarioPossuiRolePorIdAsync("u1", "r1")).ReturnsAsync(true);

        var result = await _sut.VincularUsuarioRoleAsync("sys-1", "u1", "r1");

        Assert.False(result);
        Assert.Contains(_notificador.ObterNotificacoes(), n => n.Mensagem.Contains("já possui este perfil"));
    }

    [Fact]
    public async Task VincularUsuarioRoleAsync_DadosValidos_DeveVincularERetornarTrue()
    {
        var user = new ApplicationUser { Id = "u1", Email = "u@teste.com", UserName = "u@teste.com", Nome = "User" };
        var role = new ApplicationRole { Id = "r1", Name = "Admin", SystemId = "sys-1" };

        _authRepositoryMock.Setup(x => x.ObterUsuarioPorIdAsync("u1")).ReturnsAsync(user);
        _authRepositoryMock.Setup(x => x.ObterRolePorId("r1")).ReturnsAsync(role);
        _authRepositoryMock.Setup(x => x.UsuarioPossuiRolePorIdAsync("u1", "r1")).ReturnsAsync(false);
        _authRepositoryMock.Setup(x => x.SalvaUserRolePorIdAsync("u1", "r1")).ReturnsAsync(true);

        var result = await _sut.VincularUsuarioRoleAsync("sys-1", "u1", "r1");

        Assert.True(result);
        Assert.False(_notificador.TemNotificacao());
    }
}
