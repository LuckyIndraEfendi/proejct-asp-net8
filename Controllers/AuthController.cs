using Dapper;
using Dashboard_Admin.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Data;
using BCrypt.Net;
namespace Dashboard_Admin.Controllers
{
    public class AuthController : Controller
    {
        private readonly string connectionString = "";
        private readonly string salt = BCrypt.Net.BCrypt.GenerateSalt(10);
        public AuthController(IConfiguration config)
        {
            connectionString = config.GetConnectionString("DefaultConnection");

        }
        [HttpPost]
        [Route("auth/signin")]
        public async Task<IActionResult> SignIn([FromBody] AuthSignUpModel signup)
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
    }
}
