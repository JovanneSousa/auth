namespace auth.Domain.Entities
{
    public class EmailEvent
    {
        public string EventId { get; set; } = Guid.NewGuid().ToString();
        public string Type {  get; set; }
        public string To { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public Metadados Metadata {  get; set; }

    }
}
