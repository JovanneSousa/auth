using auth.Data;
using Microsoft.EntityFrameworkCore;

namespace auth.Configuration;

public static class DbContextConfig
{
    public static WebApplicationBuilder AddDbContextConfig(this WebApplicationBuilder builder)
    {
        builder.Services.AddDbContext<ApiDbContext>(o =>
        {
        var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION");

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
