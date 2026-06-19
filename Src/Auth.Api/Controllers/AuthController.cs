using Auth.Api.Controllers;
using Auth.Domain.Models;
using Auth.Domain.ViewModel;
using Auth.Infra.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace fin_api.Controllers
{
    /// <summary>
    /// Controller responsável pelos processos de autenticação, registro e gestão de usuários.
    /// </summary>
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ApiController
    {
        private readonly IAuthService _authService;

        public AuthController
            (
            INotificador notificador,
            IAuthService authService
            ) : base(notificador)
        {
            _authService = authService;
        }

        /// <summary>
        /// Registra um novo usuário no sistema e integra com outros módulos.
        /// </summary>
        /// <param name="registerUser">Dados de registro do usuário.</param>
        /// <returns>Retorna o ID do usuário criado em caso de sucesso.</returns>
        [HttpPost("registrar")]
        public async Task<ActionResult> Registrar(RegisterUserViewModel registerUser) =>
            CustomResponse(await _authService.AdicionarUsuarioAsync(registerUser));

        /// <summary>
        /// Remove um usuário do sistema de autenticação.
        /// </summary>
        /// <param name="id">Identificador único do usuário.</param>
        /// <returns>Booleano indicando sucesso da operação.</returns>
        [HttpDelete("excluir/{id}")]
        public async Task<ActionResult<ResponsePayload<bool>>> Excluir(string id) =>
            CustomResponse(await _authService.RemoverUsuarioAsync(id));

        /// <summary>
        /// Realiza a autenticação do usuário e retorna um token JWT.
        /// </summary>
        /// <param name="loginUser">Credenciais de acesso e sistema alvo.</param>
        /// <returns>Objeto contendo o token de acesso gerado.</returns>
        [HttpPost("login")]
        public async Task<ActionResult> Login(LoginUserViewModel loginUser)
        {
            var scheme = HttpContext.Request.Scheme;
            var host = HttpContext.Request.Host.ToString();
            return CustomResponse(new { token = await _authService.LogarUsuarioAsync(loginUser, scheme, host) });
        }

        /// <summary>
        /// Endpoint de verificação de integridade da API.
        /// </summary>
        [HttpGet("health")]
        public ActionResult WakeUp() =>
            Ok();

        /// <summary>
        /// Inicia o processo de recuperação de senha enviando um e-mail com o token.
        /// </summary>
        /// <param name="data">Dados contendo o e-mail do usuário.</param>
        /// <returns>Confirmação da solicitação.</returns>
        [HttpPost("forgot-password")]
        public async Task<ActionResult<string>> ForgotPassword(ForgotPassViewModel data)
            => CustomResponse(await _authService.GerarTokenResetarSenha(data));

        /// <summary>
        /// Realiza a redefinição de senha utilizando um token válido.
        /// </summary>
        /// <param name="data">Dados contendo o token e a nova senha.</param>
        /// <returns>Resultado da operação de redefinição.</returns>
        [HttpPost("reset-pass")]
        public async Task<ActionResult<string>> ResetPass(ResetPassViewModel data)
            => CustomResponse(await _authService.RecuperarSenha(data));

        /// <summary>
        /// Lista todos os usuários cadastrados com seus respectivos vínculos de sistemas.
        /// </summary>
        /// <returns>Lista de ViewModels de usuários.</returns>
        [HttpGet("listar-usuarios")]
        public async Task<ActionResult<IEnumerable<AuthUserViewModel>>> ListarUsuarios()
            => CustomResponse(await _authService.ListarAuthUser());

        /// <summary>
        /// Obtém detalhes completos de um usuário específico por ID.
        /// </summary>
        /// <param name="id">Identificador único do usuário.</param>
        /// <returns>ViewModel com detalhes do usuário.</returns>
        [HttpGet("details-user/{id}")]
        public async Task<ActionResult<AuthUserViewModel>> ObterUsuarioPorId(string id) 
            => CustomResponse(await _authService.ObterUsuarioPorId(id));

        /// <summary>
        /// Retorna um jwt com base em um refreshToken
        /// </summary>
        /// <param name="refreshTokenViewModel">refresh token e sistema.</param>
        /// <returns>retorna token jwt em formato de string.</returns>

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestViewModel refreshTokenViewModel)
        {
            var scheme = HttpContext.Request.Scheme;
            var host = HttpContext.Request.Host.ToString();
            return CustomResponse(new {Token = await _authService.RefreshToken(refreshTokenViewModel, scheme, host) });
        }
    }
}
