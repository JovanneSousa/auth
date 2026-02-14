namespace auth.Src.Configuration;

public static class CorsConfig
{
    public static WebApplicationBuilder AddCorsConfig(this WebApplicationBuilder builder)
    {
        var allowedOrigin = builder.Configuration
            .GetSection("FrontEndSettings:AllowedApps")
            .Get<string[]>();

        if (allowedOrigin.Length == 0)
            throw new InvalidOperationException("nenhuma origem configurada em 'MEU_APP'.");

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
