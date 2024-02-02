using AS_Assignment.Helper;
using AS_Assignment.Models;
using AS_Assignment.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace AS_Assignment.Pages
{
    public class LoginModel : PageModel
    {

        [BindProperty]
        public Login LModel { get; set; }

        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IOptions<IdentityOptions> identityOptions;
        //4.4 implement logs
        private readonly LogHelper auditLogHelper;

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager,
            IOptions<IdentityOptions> identityOptions, LogHelper auditLogHelper)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.identityOptions = identityOptions;
            this.auditLogHelper = auditLogHelper;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            //5.1 implement reCAPTCHA
            var recaptchaResponse = HttpContext.Request.Form["g-recaptcha-response"];
            var recaptchaSecretKey = "6LdrCWMpAAAAALsWXGNrndT-vohcINqrXpV0Uhxd";

            var recaptchaClient = new HttpClient();
            var recaptchaResult = await recaptchaClient.GetStringAsync($"https://www.google.com/recaptcha/api/siteverify?secret={recaptchaSecretKey}&response={recaptchaResponse}");

            //convert from json
            var recaptchaData = JsonConvert.DeserializeObject<Recaptcha>(recaptchaResult);

            if (!recaptchaData.Success)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            //4.1 verifying login
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password,LModel.RememberMe, false);

                if (result.Succeeded)
                {
                    //4.4 log user log in
                    await auditLogHelper.LogUserLoginAsync(LModel.Email);

                    return RedirectToPage("Index");
                }
                else if (result.IsLockedOut)
                //4.2 lockout message
                {
                    ModelState.AddModelError("LModel.Email", "Account is locked out. Please try again later.");
                }
                else if (!result.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(LModel.Email);
                    //4.2. lockout user
                    if (user != null)
                    {
                        // Increment the count of failed access attempts
                        user.AccessFailedCount++;

                        if (user.AccessFailedCount >= userManager.Options.Lockout.MaxFailedAccessAttempts)
                        {
                            // Set the lockout end date to the current time plus the lockout duration
                            user.LockoutEnd = DateTimeOffset.UtcNow.Add(userManager.Options.Lockout.DefaultLockoutTimeSpan);
                        }

                        // Update the user in the database with the modified properties
                        await userManager.UpdateAsync(user);
                    }
                    //4.1 credential verification
                    ModelState.AddModelError("LModel.Email", "Email or password is incorrect.");

                }
            }

            return Page();
        }
    }
}
