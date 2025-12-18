namespace auth.Configuration;

public static class CorsConfig
{
    public static WebApplicationBuilder AddCorsConfig(this WebApplicationBuilder builder)
    {
        var allowedOrigin = builder.Configuration
            .GetSection("MEU_APP")
            .Get<string[]>();

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("Total",
                policy => policy
                    .AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader());
            options.AddPolicy("Production",
                policy => policy
                .WithOrigins(allowedOrigin)
                      .AllowAnyMethod()
                      .AllowCredentials()
                      .AllowAnyHeader());
        });
        return builder;
    }
}
