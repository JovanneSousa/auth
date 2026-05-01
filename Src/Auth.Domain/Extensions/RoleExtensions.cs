namespace Auth.Domain.Extensions
{
    public static class RoleExtensions
    {
        public static string GetSystemPrefix(this string roleName)
        {
            return roleName.Split("_")[0];
        }
    }
}
