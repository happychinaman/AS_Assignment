using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;


namespace AS_Assignment.Models
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        //4.4 create db for logs
        public DbSet<Logs> Logs { get; set; }


        private readonly IConfiguration _configuration;

        public AuthDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AuthConnectionString");
            optionsBuilder.UseSqlServer(connectionString);
        }
    }
}
