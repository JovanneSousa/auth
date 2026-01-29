using auth.Configuration;
using auth.Infra.MessageBus;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
await builder
    .AddCorsConfig()
    .AddIdentityConfig()
    .AddDbContextConfig()
    .AddPermissionConfig()
    .AddDiConfig();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.Configure<FrontEndSettings>(
    builder.Configuration.GetSection("FrontEndSettings"));

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

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
