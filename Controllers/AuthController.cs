using Dapper;
using Dashboard_Admin.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Data;
using BCrypt.Net;
using Microsoft.AspNetCore.Authorization;


namespace Dashboard_Admin.Controllers
{
    public class AuthController : Controller
    {
        private readonly string connectionString = "";
        private readonly string salt = BCrypt.Net.BCrypt.GenerateSalt(10);
        private readonly JwtSettings jwtSettings;
        public AuthController(IConfiguration config ,JwtSettings jwtSettings)
        {
            connectionString = config.GetConnectionString("DefaultConnection");
            this.jwtSettings = jwtSettings;

        }
        [HttpPost]
        [Route("auth/signup")]
        public async Task<IActionResult> SignUp([FromBody] AuthSignUpModel signup)
        {
            var conn = new SqlConnection(connectionString);
            if (conn.State == ConnectionState.Closed) await conn.OpenAsync();

            var trx = conn.BeginTransaction();
            try
            {
                var p = new DynamicParameters();
                p.Add("@Username", signup.username);
                p.Add("@Email", signup.email);
                p.Add("@Password", BCrypt.Net.BCrypt.HashPassword(signup.password,salt));

                var result = await conn.ExecuteAsync("usp_InsertCustomer", p, commandType: CommandType.StoredProcedure,transaction: trx);
             
                await trx.CommitAsync();

                return Json(new { status_code = 200, message = "Registration Successful",data= result });

            }
            catch (Exception err)
            {
                return StatusCode(500, new { status_code = 500, message = err.Message });
            }
            finally
            {
                conn.Close();
            }
        }


        [HttpPost]
        [Route("auth/signin")]
        public async Task<IActionResult> SignIn([FromBody] AuthSignInModel signin)
        {
            var conn = new SqlConnection(connectionString);
            if (conn.State == ConnectionState.Closed) await conn.OpenAsync();
            try
            {
                var p = new { Email = signin.email };
                var customer = await conn.QuerySingleOrDefaultAsync<dynamic>("usp_SignInCustomer", p);
                if (customer != null)
                {
                    bool isPasswordValid = BCrypt.Net.BCrypt.Verify(signin.password, customer.password);

                    if (isPasswordValid)
                    {
                        var tokenHelper = new JwtTokenHelper(jwtSettings.SecretKey, jwtSettings.Issuer, jwtSettings.Audience);
                        var token = tokenHelper.GenerateToken(signin.email);
                        Response.Cookies.Append("jwt_token", token, new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.Strict,
                            Expires = DateTime.UtcNow.AddMinutes(30)
                        });
                        return Json(new { status_code = 200, message = "Authentication successful" });
                    }
                    else
                    {
                        return StatusCode(400,new { status_code = 400, message = "Invalid Credentials" });
                    }
                }
                else
                {
                    return StatusCode(404,new { status_code = 400, message = "Email not found" });
                }
            }
            catch(Exception err)
            {
                return StatusCode(500, new { status_code = 500, message = err.Message });
            }
            finally
            {
               await conn.CloseAsync();
            }
        }

        [Authorize]
        [HttpGet]
        [Route("auth/allusers")]

        public async Task<IActionResult> GetAllUser()
        {
            var conn = new SqlConnection(connectionString);
            if (conn.State == ConnectionState.Closed) await conn.OpenAsync();
            try
            {
                var sql = "SELECT * FROM dbo.Customers";
                var getAllUser = await conn.QuerySingleOrDefaultAsync<dynamic>(sql,null);
                if (getAllUser != null)
                {
                    return Json(getAllUser);
                } else
                {
                    return Json(new { status_code = 200, message = "User not found" });
                }
            }
            catch (Exception err)
            {
                return StatusCode(500, new { status_code = 500, message = err.Message });
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
    }
}
