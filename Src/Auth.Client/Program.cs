using Auth.Client;
using Auth.Client.Service;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.JSInterop;
using MudBlazor.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");
builder.Services.AddMudServices();

var baseAddress = builder.HostEnvironment.IsDevelopment()
    ? new Uri("http://localhost:5071")
    : new Uri(builder.HostEnvironment.BaseAddress);

builder.Services.AddScoped<IAuthStateService>(sp =>
    new AuthStateService(
        new HttpClient { BaseAddress = baseAddress },
        sp.GetRequiredService<IJSRuntime>()));

builder.Services.AddScoped<AuthHeaderHandler>();

builder.Services.AddScoped(sp =>
{
    var handler = sp.GetRequiredService<AuthHeaderHandler>();
    handler.InnerHandler = new HttpClientHandler();
    return new HttpClient(handler)
    {
        BaseAddress = baseAddress
    };
});

builder.Services.AddScoped<IApiService, ApiService>();

await builder.Build().RunAsync();
