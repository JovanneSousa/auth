using Auth.Domain.ViewModel;

namespace Auth.Infra.Interfaces;

public interface IAuthService
{
    Task<bool> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser);
    Task<bool> GerarTokenResetarSenha(ForgotPassViewModel data);
    Task<bool> RecuperarSenha(ResetPassViewModel data);
    Task<IEnumerable<AuthUserViewModel>> ListarAuthUser();
    Task<AuthUserViewModel> ObterUsuarioPorId(string id);
}
