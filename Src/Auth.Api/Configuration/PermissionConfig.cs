using Auth.Domain.Entities;
using System.Text.Json;

namespace Auth.Api.Configuration
{
    public static class PermissionConfig
    {
        public static WebApplicationBuilder AddPermissionConfig(this WebApplicationBuilder builder)
        {
            var permissionsJson = Environment.GetEnvironmentVariable("PERMISSIONS_MAP");

            if (string.IsNullOrWhiteSpace(permissionsJson) || permissionsJson == null || permissionsJson.Length <= 0)
                throw new Exception("PERMISSIONS_MAP não configurada.");

            var data =
                JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, List<string>>>>(
                    permissionsJson,
                    new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

            builder.Services.AddSingleton(new PermissionModel
            {
                Systems = data!
            });

            return builder;
        }
    }
}
