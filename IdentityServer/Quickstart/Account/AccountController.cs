using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.Identity.Mongo.Model;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Quickstart.Account
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IUserStore<MongoUser> _userStore;
        private readonly UserManager<MongoUser> _userManager;
        private readonly ILookupNormalizer _lookupNormalizer;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IIdentityProviderStore _identityProviderStore;
        private readonly IEventService _events;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IIdentityProviderStore identityProviderStore,
            IEventService events,
            IUserStore<MongoUser> userStore, 
            UserManager<MongoUser> userManager,
            ILookupNormalizer lookupNormalizer)
        {
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _identityProviderStore = identityProviderStore;
            _events = events;
            _userStore = userStore;
            _userManager = userManager;
            _lookupNormalizer = lookupNormalizer;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }
        
        [HttpGet]
        public IActionResult Register(string returnUrl, bool rememberLogin)
        {
            var registerInputModel = new RegisterInputModel
            {
                ReturnUrl = returnUrl,
                RememberLogin = rememberLogin
            };

            return View(registerInputModel);
        }
        
        [HttpGet]
        public IActionResult ForgotPassword(string returnUrl, string email)
        {
            var model = new ForgotPasswordInputModel()
            {
                Email = email,
                ReturnUrl = returnUrl,
                EmailSent = false
            };

            return View(model);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordInputModel model, string button)
        {
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (button == "cancel")
            {
                var login = new LoginInputModel
                {
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("Login", login);
            }
            
            var newModel = new ForgotPasswordInputModel()
            {
                ReturnUrl = model.ReturnUrl,
                EmailSent = true
            };
            
            return View(newModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterInputModel model, string button)
        {
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (button == "cancel")
            {
                var login = new LoginInputModel
                {
                    RememberLogin = model.RememberLogin,
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("Login", login);
            }
            
            if (model.Password != model.RepeatPassword)
            {
                ModelState.AddModelError("PasswordsNotEqual", "Passwords are not equal");
            }
            
            if (ModelState.IsValid)
            {
                var claimsToAdd = new List<IdentityUserClaim<string>> {
                    new()
                    {
                        ClaimType = JwtClaimTypes.GivenName,
                        ClaimValue = model.Name
                    }
                };
                var account = new MongoUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Claims = claimsToAdd
                };

                var result = await _userManager.CreateAsync(account, model.Password);

                if (result.Succeeded)
                {
                    return await LoginUser(new LoginInputModel
                    {
                        Email = model.Email,
                        Password = model.Password,
                        RememberLogin = model.RememberLogin,
                        ReturnUrl = model.ReturnUrl
                    }, account, context);
                }

                foreach (var identityError in result.Errors)
                {
                    ModelState.AddModelError(identityError.Code, identityError.Description);
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (button == "register")
            {
                var register = new RegisterInputModel
                {
                    RememberLogin = model.RememberLogin,
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("Register", register);
            }
            
            if (button == "forgot-pw")
            {
                var register = new ForgotPasswordInputModel
                {
                    Email = model.Email,
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("ForgotPassword", register);
            }
            
            if (button == "login")
            {
                var mail = _lookupNormalizer.NormalizeName(model.Email);
                var user = await _userStore.FindByNameAsync(mail, CancellationToken.None);
                var identityResult = await _userManager.CheckPasswordAsync(user, model.Password);
                
                if (identityResult)
                {
                    return await LoginUser(model, user, context);
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Email, "invalid credentials", clientId:context?
                .Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
                ModelState.Remove("Email");
            }

            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        private async Task<IActionResult> LoginUser(LoginInputModel model, MongoUser user, AuthorizationRequest context)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.UserName, clientId: context?.Client.ClientId));

            // only set explicit expiration here if user chooses "remember me". 
            // otherwise we rely upon expiration configured in cookie middleware.
            AuthenticationProperties props = null;
            if (AccountOptions.AllowRememberLogin && model.RememberLogin)
            {
                props = new AuthenticationProperties
                {
                    IsPersistent = true,
                    AllowRefresh = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                };
            }

            // issue authentication cookie with subject ID and username
            var isuser = new IdentityServerUser(user.Id.ToString())
            {
                DisplayName = user.UserName,
            };

            await HttpContext.SignInAsync(isuser, props);

            if (context != null)
            {
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage("Redirect", model.ReturnUrl);
                }

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                return Redirect(model.ReturnUrl);
            }

            // request for a local page
            if (Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            if (string.IsNullOrEmpty(model.ReturnUrl))
            {
                return Redirect("~/");
            }

            throw new Exception("invalid return URL");
        }

        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();
                // delete session from MS Identity
                await HttpContext.SignOutAsync("Identity.Application");

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return Redirect(vm.PostLogoutRedirectUri ?? "/");
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var dyanmicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
                .Where(x => x.Enabled)
                .Select(x => new ExternalProvider
                {
                    AuthenticationScheme = x.Scheme,
                    DisplayName = x.DisplayName
                });
            providers.AddRange(dyanmicSchemes);

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}
