using Auth.Application.DTOs;
using Auth.Application.Extensions;
using Auth.Domain.Entities;
using Auth.Domain.ViewModel;
using Xunit;

namespace Auth.UnitTests;

public class DomainAndExtensionsTests
{
    [Fact]
    public void RefreshToken_isValid_DeveCompararEmUtcCorretamente()
    {
        var valido = new RefreshToken
        {
            UserName = "user@teste.com",
            ExpirationDate = DateTime.UtcNow.AddMinutes(10)
        };
        var expirado = new RefreshToken
        {
            UserName = "user@teste.com",
            ExpirationDate = DateTime.UtcNow.AddMinutes(-1)
        };

        Assert.True(valido.isValid());
        Assert.False(expirado.isValid());
    }

    [Fact]
    public void SystemEntity_Validate_DeveRetornarErrosParaCamposVazios()
    {
        var entity = new SystemEntity { Id = "", Name = " ", Url = "" };

        Assert.False(entity.IsValid());
        Assert.Equal(3, entity.Validate().Count());
    }

    [Fact]
    public void ApplicationClaimViewModelExtensions_ToClaim_DeveNormalizarEmUpperCase()
    {
        var vm = new ApplicationClaimViewModel("r1", "fin:trn_criar");

        var claim = vm.ToClaim();

        Assert.Equal("permission", claim.Type);
        Assert.Equal("FIN:TRN_CRIAR", claim.Value);
    }

    [Fact]
    public void SystemDapperDTO_ToViewModel_ComRoleInvalida_NaoDeveAdicionarPermissaoVazia()
    {
        var sistemaDto = new SystemDapperDTO
        {
            SystemId = "s1",
            Name = "Auth",
            Url = "https://auth.local",
            Permissoes = []
        };
        var roleInvalida = new ApplicationRoleDapperDTO
        {
            RoleId = "",
            Name = "",
            Claims = []
        };

        var vm = sistemaDto.ToViewModel(roleInvalida);

        Assert.Empty(vm.Permissoes);
    }
}
