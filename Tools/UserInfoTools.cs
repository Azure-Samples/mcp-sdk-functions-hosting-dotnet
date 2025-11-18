using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Http;
using ModelContextProtocol;
using ModelContextProtocol.Server;
using System.ComponentModel;

namespace QuickstartWeatherServer.Tools;

[McpServerToolType]
public sealed class UserInfoTools
{
    [McpServerTool, Description("Get current logged-in user information from Microsoft Graph using Azure App Service authentication and On-Behalf-Of flow.")]
    public static async Task<string> GetCurrentUser(IHttpContextAccessor httpContextAccessor)
    {
        var httpContext = httpContextAccessor.HttpContext;
        
        // Check if we have authentication headers
        if (httpContext == null || httpContext.Request.Headers == null)
        {
            return System.Text.Json.JsonSerializer.Serialize(new
            {
                authenticated = false,
                message = "No HTTP context or headers found"
            });
        }

        var headers = httpContext.Request.Headers;

        try
        {
            // Get the auth token from Authorization header and remove the "Bearer " prefix
            if (!headers.TryGetValue("Authorization", out var authHeaderValue) || 
                string.IsNullOrEmpty(authHeaderValue))
            {
                return System.Text.Json.JsonSerializer.Serialize(new
                {
                    authenticated = false,
                    message = "No authorization header found"
                });
            }

            var authToken = authHeaderValue.ToString().Split(' ').LastOrDefault();
            if (string.IsNullOrEmpty(authToken))
            {
                return System.Text.Json.JsonSerializer.Serialize(new
                {
                    authenticated = false,
                    message = "Invalid authorization header format"
                });
            }

            // Get configuration from environment variables (set by App Service Authentication)
            var tokenExchangeAudience = Environment.GetEnvironmentVariable("TokenExchangeAudience") ?? "api://AzureADTokenExchange";
            var publicTokenExchangeScope = $"{tokenExchangeAudience}/.default";
            var federatedCredentialClientId = Environment.GetEnvironmentVariable("OVERRIDE_USE_MI_FIC_ASSERTION_CLIENTID");
            var clientId = Environment.GetEnvironmentVariable("WEBSITE_AUTH_CLIENT_ID");
            var tenantId = Environment.GetEnvironmentVariable("WEBSITE_AUTH_AAD_ALLOWED_TENANTS");

            if (string.IsNullOrEmpty(federatedCredentialClientId) || 
                string.IsNullOrEmpty(clientId) || 
                string.IsNullOrEmpty(tenantId))
            {
                return System.Text.Json.JsonSerializer.Serialize(new
                {
                    authenticated = false,
                    message = "Missing required environment variables for authentication"
                });
            }

            // Create managed identity credential for the federated credential
            var managedIdentityCredential = new ManagedIdentityCredential(federatedCredentialClientId);

            // Create On-Behalf-Of credential using the constructor signature:
            // OnBehalfOfCredential(tenantId, clientId, clientSecret, userAssertionToken, options)
            // But we need to use client assertion instead of client secret
            var oboCredential = new OnBehalfOfCredential(
                tenantId,
                clientId,
                async (cancellationToken) =>
                {
                    var token = await managedIdentityCredential.GetTokenAsync(
                        new TokenRequestContext([publicTokenExchangeScope]),
                        cancellationToken);
                    return token.Token;
                },
                authToken);

            // Get token from OBO credential for Graph API
            var graphToken = await oboCredential.GetTokenAsync(
                new TokenRequestContext(["https://graph.microsoft.com/.default"]),
                default);

            // Call Microsoft Graph API directly using HttpClient (matching TypeScript implementation)
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", graphToken.Token);
            
            var graphResponse = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/me");
            
            if (!graphResponse.IsSuccessStatusCode)
            {
                var errorContent = await graphResponse.Content.ReadAsStringAsync();
                return System.Text.Json.JsonSerializer.Serialize(new
                {
                    authenticated = false,
                    message = $"Failed to retrieve user information: {graphResponse.StatusCode}",
                    error = errorContent
                });
            }

            var graphData = await graphResponse.Content.ReadAsStringAsync();
            var user = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(graphData);

            // Mask sensitive information (for demo purposes)
            var maskedUser = new
            {
                authenticated = true,
                user = new
                {
                    displayName = user.GetProperty("displayName").GetString(),
                    userPrincipalName = user.TryGetProperty("userPrincipalName", out var upn) ? "[MASKED]" : null,
                    mail = user.TryGetProperty("mail", out var m) ? "[MASKED]" : null,
                    id = user.TryGetProperty("id", out var userId) ? userId.GetString() : null,
                    businessPhones = user.TryGetProperty("businessPhones", out var bp) 
                        ? bp.EnumerateArray().Select(_ => "[MASKED]").ToArray() 
                        : Array.Empty<string>()
                },
                message = "Successfully retrieved user information from Microsoft Graph"
            };

            return System.Text.Json.JsonSerializer.Serialize(maskedUser, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
        catch (Exception ex)
        {
            var hostname = Environment.GetEnvironmentVariable("WEBSITE_HOSTNAME");
            var errorOutput = new
            {
                authenticated = false,
                message = $"Error during token exchange and Graph API call: {ex.Message}. " +
                         (!string.IsNullOrEmpty(hostname) 
                             ? $"You're logged in but might need to grant consent to the application. Open a browser to the following link to consent: https://{hostname}/.auth/login/aad?post_login_redirect_uri=https://{hostname}/authcomplete"
                             : "You might need to grant consent to the application."),
                error = ex.GetType().Name
            };

            return System.Text.Json.JsonSerializer.Serialize(errorOutput, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
    }
}
