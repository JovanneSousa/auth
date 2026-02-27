namespace Auth.Domain.Entities
{
    public class PermissionModel
    {
        public Dictionary<string, Dictionary<string, List<string>>> Systems { get; set; } = new();
    }
}
