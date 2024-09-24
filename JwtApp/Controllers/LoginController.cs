using JwtApp.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly ILogger<LoginController> _logger;
        private IConfiguration _config;

        public LoginController(IConfiguration config, ILogger<LoginController> logger)
        {
            _config = config;
            _logger = logger;
        }

        [HttpPost]
        public async Task<IActionResult> Login(UserLogin userLogin)
        {
            try
            {
                _logger.LogInformation("Executing Logging Controller");
                var user = Authenticate(userLogin);
                if (user is not null)
                {
                    var token = GenerateToken(user);
                    _logger.LogError("{@Username} is authenticated sucessfully", user.Username);
                    return Ok(token);
                }

                throw new InvalidOperationException("User is not found");
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex.Message);
            }
        }

        private string GenerateToken(UserModel user)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]))
                    ?? throw new InvalidOperationException("security key is null or empty");

                var issuer = _config["Jwt:Issuer"]
                    ?? throw new ArgumentException("issuer varibale is null or empty");

                var audience = _config["Jwt:Issuer"]
                    ?? throw new ArgumentException("issuer varibale is null or empty");

                var credintials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier,  user.Username),
                    new Claim(ClaimTypes.Email, user.EmailAddress),
                    new Claim(ClaimTypes.GivenName, user.GivenName),
                    new Claim(ClaimTypes.Surname, user.Surname),
                    new Claim(ClaimTypes.Role, user.Role),
                };

                var token = new JwtSecurityToken(issuer,
                    audience,
                    claims,
                    expires: DateTime.Now.AddMinutes(15),
                    signingCredentials: credintials);

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (Exception)
            {
                return "An error occurred while generating token";
            }
        }

        private UserModel Authenticate(UserLogin userLogin)
        {
            var currentUser = UserConstants.Users
                  .FirstOrDefault(u => u.Username.Trim().Equals(userLogin.Username.Trim(), StringComparison.OrdinalIgnoreCase)
                  && u.Password.Equals(userLogin.Password));

            return currentUser;
        }
    }
}