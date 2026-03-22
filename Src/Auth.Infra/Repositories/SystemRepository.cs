//using Auth.Application.Data;
//using Auth.Application.Repositories;
//using Auth.Domain.Entities;
//using Auth.Infra.Interfaces;
//using Microsoft.EntityFrameworkCore;

//namespace Auth.Infra.Repositories
//{
//    public class SystemRepository : BaseRepository, ISystemRepository
//    {
//        private readonly ApplicationDbContext _context;

//        public SystemRepository(ApplicationDbContext context)
//        {
//            _context = context;
//        }

//        public async Task<bool> AdicionarAsync(SystemEntity system) 
//            => await ExecuteAsync(async () =>
//                {
//                    await _context.SystemEntity.AddAsync(system);
//                    await _context.SaveChangesAsync();
//                    return true;
//                });

//        public async Task<IEnumerable<SystemEntity>> ObterTodosSistemasAsync()
//            => await ExecuteAsync(async () => await _context.SystemEntity.ToListAsync());
//    }
//}
