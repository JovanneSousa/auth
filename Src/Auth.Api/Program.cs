using Auth.Api.Configuration;
using Auth.Configuration;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
await builder
    .AddCorsConfig()
    .AddIdentityConfig()
    .AddDbContextConfig()
    .AddPermissionConfig()
    .AddSettingsConfig()
    .AddDiConfig();

builder.Services.AddRazorPages();

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
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();
app.MapRazorPages();

app.MapFallbackToFile("index.html");

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
