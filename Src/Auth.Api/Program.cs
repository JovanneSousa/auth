using Auth.Api.Configuration;
using Auth.Infra.Data;
using Auth.Infra.Identity;
using Jovanne.Jwks;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
await builder
    .AddDbContextConfig()
    .AddCorsConfig()
    .AddSettingsConfig()
    .AddDiConfig();

builder.Services
    .AddRazorPages();

builder.Services
    .AddJovanneJwksFull<
        ApplicationUser, 
        ApplicationRole, 
        ApplicationDbContext>
        (builder.Configuration, builder.Environment.IsDevelopment());

builder = await builder.AddMessageBus();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Auth Api",
        Version = "v1"
    }));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors("Total");
} else
{
    app.UseCors("Production");
}
// app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.UseJwksDiscovery();

app.MapControllers();
app.MapRazorPages();

app.MapFallbackToFile("index.html");

app.Run();