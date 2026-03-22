using Auth.Infra.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth.Application.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        //public DbSet<SystemEntity> SystemEntity { get; set; }

        //protected override void OnModelCreating(ModelBuilder builder)
        //{
        //    base.OnModelCreating(builder);
        //    builder.Entity<SystemEntity>(entity =>
        //    {
        //        entity.HasKey(s => s.Id);

        //        entity.Property(s => s.Name)
        //            .IsRequired()
        //            .HasMaxLength(100);

        //        entity.Property(s => s.Url)
        //            .HasMaxLength(200);
        //    });

        //    builder.Entity<ApplicationRole>(entity =>
        //    {
        //        entity.Property(r => r.SystemId)
        //            .IsRequired();

        //        entity.HasIndex(r => r.SystemId);
        //    });
        //}
    }
}
