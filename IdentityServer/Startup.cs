﻿using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using AspNetCore.Identity.Mongo;
using AspNetCore.Identity.Mongo.Model;
using IdentityServer.Quickstart.Mail;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer
{
    public class Startup
    {
        public IWebHostEnvironment WebEnvironment { get; }

        public Startup(IWebHostEnvironment webEnvironment)
        {
            WebEnvironment = webEnvironment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddTransient<IMailService, MailService>();
            services.AddTransient<IMailRenderer, MailRenderer>();
            services.AddControllersWithViews();

            services.AddIdentityMongoDbProvider<MongoUser, MongoRole>(identityOptions =>
            {
                identityOptions.Password.RequireNonAlphanumeric = false;
                identityOptions.Password.RequireUppercase = false;
                identityOptions.User.RequireUniqueEmail = true;
            }, mongoIdentityOptions => {
                mongoIdentityOptions.ConnectionString = Environment.GetEnvironmentVariable("MONGO_DB_CONNECTION_STRING");
            }).AddDefaultTokenProviders();

            services.AddIdentityServer(options =>
                {
                    options.EmitStaticAudienceClaim = true;
                })
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(Config.ApiScopes)
                .AddInMemoryClients(Config.Clients)
                .AddAspNetIdentity<MongoUser>();
            
            // services.AddAuthentication()
            //     .AddGoogle("Google", options =>
            //     {
            //         options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //
            //         options.ClientId = "<insert here>";
            //         options.ClientSecret = "<insert here>";
            //     });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (WebEnvironment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();
            app.UseRouting();
            
            // this is so caddy can forward to http and the openid config is fine
            app.Use((context, next) =>
            {
                context.Request.Scheme = "https";
                return next();
            });
            app.UseIdentityServer();
            app.UseAuthorization();
            
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
