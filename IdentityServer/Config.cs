﻿using System;
using Duende.IdentityServer.Models;
using System.Collections.Generic;
using Duende.IdentityServer;

namespace IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            { 
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            { };

        public static IEnumerable<Client> Clients =>
            new Client[]
            {
                new Client
                {
                    ClientId = "fading-flame",
                    ClientSecrets = { new Secret(Environment.GetEnvironmentVariable("FADING_FLAME_SECRET").Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,
            
                    RedirectUris = { "https://localhost:5000/signin-oidc", $"https://{Environment.GetEnvironmentVariable("IDENTITY_BASE_URI")}/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:5000/signout-callback-oid", $"https://{Environment.GetEnvironmentVariable("IDENTITY_BASE_URI")}/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email
                    }
                }
                
            };
    }
}