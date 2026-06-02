using Auth.Domain.ViewModel;

namespace Auth.Infra.Interfaces;

/// <summary>
/// Interface que define as operações de negócio para autenticação e gestão de usuários.
/// </summary>
public interface IAuthService
{
    /// <summary>
    /// Realiza o cadastro de um novo usuário, validando se já existe e integrando com outros sistemas.
    /// </summary>
    Task<string?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);

    /// <summary>
    /// Remove um usuário da base de dados.
    /// </summary>
    Task<bool> RemoverUsuarioAsync(string id);

    /// <summary>
    /// Lista todos os usuários e seus vínculos com sistemas.
    /// </summary>
    Task<IEnumerable<AuthUserViewModel>> ListarAuthUser();

    /// <summary>
    /// Obtém os dados de um usuário pelo seu identificador único.
    /// </summary>
    Task<AuthUserViewModel?> ObterUsuarioPorId(string id);

    /// <summary>
    /// Valida credenciais, gera token JWT e verifica permissões de acesso ao sistema.
    /// </summary>
    Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser, string scheme, string host);

    /// <summary>
    /// Gera um token de redefinição de senha e dispara o evento de e-mail.
    /// </summary>
    Task<bool> GerarTokenResetarSenha(ForgotPassViewModel data);

    /// <summary>
    /// Processa a alteração de senha utilizando o token de recuperação.
    /// </summary>
    Task<bool> RecuperarSenha(ResetPassViewModel data);
}
