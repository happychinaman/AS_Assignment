using AS_Assignment.Models;

namespace AS_Assignment.Helper
{
    public class LogHelper
    {
        //4.4 implement logs
        private readonly ILogger<LogHelper> _logger;
        private readonly AuthDbContext _context;

        public LogHelper(ILogger<LogHelper> logger, AuthDbContext context)
        {
            _logger = logger;
            //calls db
            _context = context;
        }

        //user log in log
        public async Task LogUserLoginAsync(string userId)
        {
            await LogUserActivityAsync(userId, "User Logged In");
        }

        //user log out log
        public async Task LogUserLogoutAsync(string userId)
        {
            await LogUserActivityAsync(userId, "User Logged Out");
        }

        private async Task LogUserActivityAsync(string userId, string action)
        {
            var auditLog = new Logs
            {
                UserId = userId,
                Action = action,
                Time = DateTime.UtcNow
            };

            // add the auditLog to the database context and save changes
            _context.Logs.Add(auditLog);
            await _context.SaveChangesAsync();

            // log info
            _logger.LogInformation("Audit log: {Action} for user {UserId}", action, userId);
        }
    }
}
