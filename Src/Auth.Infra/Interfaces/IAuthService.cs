using Auth.Domain.ViewModel;

namespace Auth.Infra.Interfaces;

public interface IAuthService
{
    Task<string?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    Task<bool> RemoverUsuarioAsync(string id);
    Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser, string scheme, string host);
    Task<bool> GerarTokenResetarSenha(ForgotPassViewModel data);
    Task<bool> RecuperarSenha(ResetPassViewModel data);
    Task<IEnumerable<AuthUserViewModel>> ListarAuthUser();
    Task<AuthUserViewModel?> ObterUsuarioPorId(string id);
}
