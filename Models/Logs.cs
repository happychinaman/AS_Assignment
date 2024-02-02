namespace AS_Assignment.Models
{
    public class Logs
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public string? Action { get; set; }
        public DateTime Time { get; set; }
    }
}
