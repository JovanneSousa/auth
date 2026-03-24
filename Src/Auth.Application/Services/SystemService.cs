using Auth.Domain.Entities;
using Auth.Domain.Interfaces;
using Auth.Infra.Interfaces;

namespace Auth.Application.Services
{
    public class SystemService : BaseService, ISystemService
    {
        private readonly ISystemRepository _systemRepository;
        public SystemService(
            INotificador notificador, 
            ISystemRepository systemRepository) 
            : base(notificador)
        {
            _systemRepository = systemRepository;
        }

        public async Task<bool> AdicionaSistemaAsync(SystemEntity sistema)
        {
            return await ExecuteAsync(
                async () => await _systemRepository.AdicionarAsync(sistema));
        }

        public async Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync() =>
            await ExecuteAsync(async () => await _systemRepository.ObterTodosSistemasAsync());
    }
}
