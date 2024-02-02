using AS_Assignment.Models;
using AS_Assignment.ViewModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AS_Assignment.Pages
{

	public class RegisterModel : PageModel
	{
		private readonly UserManager<ApplicationUser> userManager;
		private readonly SignInManager<ApplicationUser> signInManager;
		
		//2.5 implement encryption
		private readonly IDataProtectionProvider dataProtectionProvider;


		[BindProperty]
		public Register RModel { get; set; }

		public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IDataProtectionProvider dataProtectionProvider)
		{
			this.userManager = userManager;
			this.signInManager = signInManager;

			this.dataProtectionProvider = dataProtectionProvider;
		}

		public void OnGet() { }

		public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
				//1.2 duplicate email & rectify issue
				var existingUser = await userManager.FindByEmailAsync(RModel.Email);

				if (existingUser != null)
				{
					ModelState.AddModelError("RModel.Email", "Email address is already registered.");
					return Page();
				}

				// 1.1 save member info
				var user = new ApplicationUser()
				{
					UserName = RModel.Email,
					FullName = ProtectData(RModel.FullName),
					CreditCardNo = ProtectData(RModel.CreditCardNo),
					PhoneNumber = RModel.MobileNo,
                    DeliveryAddress = RModel.DeliveryAddress,
					ShippingAddress = RModel.ShippingAddress,
					Email = RModel.Email,
				};

				if (RModel.ImageFile != null && RModel.ImageFile.Length > 0)
				{

					//convert to bytes
					using (var memoryStream = new MemoryStream())
					{
						await RModel.ImageFile.CopyToAsync(memoryStream);
						user.Image = memoryStream.ToArray();
					}
				}

				// 2.4 password protection protection (hashed password)
				var result = await userManager.CreateAsync(user, RModel.Password);

				if (result.Succeeded)
				{
					await signInManager.SignInAsync(user, false);
					return RedirectToPage("Index");
				}

				//error validation
				foreach (var error in result.Errors)
				{
					ModelState.AddModelError("", error.Description);
				}
			}

			return Page();
		}


		// 2.5 encryption of data 
		private string ProtectData(string data)
		{
			var protector = dataProtectionProvider.CreateProtector("YourPurpose");

			return protector.Protect(data);
		}
	}
}
