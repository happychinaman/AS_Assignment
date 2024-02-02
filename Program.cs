using AS_Assignment.Helper;
using AS_Assignment.Models;
using Microsoft.AspNetCore.Identity;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddDbContext<AuthDbContext>();



//3.1 Session Management online reference
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache(); // Save session in memory
builder.Services.AddSession(options =>
{
    //3.2 session timeout (broken)
    options.IdleTimeout = TimeSpan.FromSeconds(5);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});


//4.2 rate limiting
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{

    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 3; //attempts
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); //duration
})
.AddEntityFrameworkStores<AuthDbContext>();

// Configure Application Cookie
builder.Services.ConfigureApplicationCookie(config =>
{
    config.LoginPath = "/Login";
});

//4.4 implement logs
builder.Services.AddScoped<LogHelper>();

var app = builder.Build();



// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseSession();

app.MapRazorPages();

app.Run();
