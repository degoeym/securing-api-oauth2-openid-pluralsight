using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Services;
using Marvin.IDP.Entities;
using Marvin.IDP.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http.Authentication;

namespace Marvin.IDP.Controllers.UserRegistration
{
    public class UserRegistrationController : Controller
    {
        private readonly IMarvinUserRepository _marvinUserRepository;
        private readonly IIdentityServerInteractionService _interaction;

        public UserRegistrationController(IMarvinUserRepository marvinUserRepository,
            IIdentityServerInteractionService interaction)
        {
            _marvinUserRepository = marvinUserRepository;
            _interaction = interaction;
        }

        [HttpGet]
        public IActionResult RegisterUser(RegistrationInputModel registrationInputModel)
        {
            var vm = new RegisterUserViewModel()
            {
                ReturnUrl = registrationInputModel.ReturnUrl,
                Provider = registrationInputModel.Provider,
                ProviderUserId = registrationInputModel.ProviderUserId
            };
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterUser(RegisterUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var userToCreate = new User()
                {
                    Password = model.Password,
                    Username = model.Username,
                    IsActive = true,
                    Claims = new List<UserClaim>()
                    {
                        new UserClaim("country", model.Country),
                        new UserClaim("address", model.Address),
                        new UserClaim("given_name", model.Firstname),
                        new UserClaim("family_name", model.Lastname),
                        new UserClaim("email", model.Email),
                        new UserClaim("subscriptionlevel", "FreeUser")
                    }
                };

                // if we're provisioning a user via external login, we must add the provider &
                // user id at the provider ot this uer's logins
                if (model.IsProvisioningFromExternal)
                {
                    userToCreate.Logins.Add(new UserLogin()
                    {
                        LoginProvider = model.Provider,
                        ProviderKey = model.ProviderUserId
                    });
                }

                _marvinUserRepository.AddUser(userToCreate);

                if (!_marvinUserRepository.Save())
                {
                    throw new Exception($"Creating a user failed.");
                }

                if (!model.IsProvisioningFromExternal)
                {
                    await HttpContext.Authentication.SignInAsync(userToCreate.SubjectId,
                                userToCreate.Username); 
                }

                if(_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }

                return Redirect("~/");
            }

            return View(model);
        }
    }
}
