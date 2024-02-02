using AS_Assignment.Models;
using AS_Assignment.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AS_Assignment.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        [BindProperty]
        public ChangePassword ChangePasswordViewModel { get; set; }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            //refresh page
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userManager.GetUserId(User)}'.");
            }

            //9.3 changes the user's password
            var changePasswordResult = await userManager.ChangePasswordAsync(user, ChangePasswordViewModel.CurrentPassword, ChangePasswordViewModel.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                // If password change fails, add errors to model state
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return Page();
            }

            // Refresh the user's sign-in cookie
            await signInManager.RefreshSignInAsync(user);
            return RedirectToPage("/Index");
        }
    }
}
