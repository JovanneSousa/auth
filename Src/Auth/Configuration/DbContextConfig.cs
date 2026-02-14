using auth.Src.Data;
using Microsoft.EntityFrameworkCore;

namespace auth.Src.Configuration;

public static class DbContextConfig
{
    public static WebApplicationBuilder AddDbContextConfig(this WebApplicationBuilder builder)
    {
        builder.Services.AddDbContext<ApiDbContext>(o =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

            if(string.IsNullOrEmpty(connectionString))
                throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

            o.UseNpgsql(connectionString,
            npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 5,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorCodesToAdd: new[] { "57P03" }
                    );
            });
        });

        return builder;
    }
}
