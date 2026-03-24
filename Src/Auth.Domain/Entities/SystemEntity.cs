namespace Auth.Domain.Entities
{
    public class SystemEntity
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; }
        public string Url { get; set; }
    }
}
