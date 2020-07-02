using System.Security.Claims;
using System.Threading.Tasks;
using KalumAutenticacion.Context;
using KalumAutenticacion.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace KalumAutenticacion.Controllers
{
    [Route("KalumAutenticacion/v1/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly ApplicationDbContext context;
        public UsuariosController(UserManager<ApplicationUser> userManager,ApplicationDbContext context)
        {
            this.context = context;
            this.userManager=userManager;
        }
        [HttpPost("AsignarUsuarioRol")]
        public async Task<ActionResult> AsignarRolUsuario([FromBody] UserRol userRol)
        {
            var usuario = await userManager.FindByIdAsync(userRol.UserId);
            if(usuario==null)
            {
                return NotFound();
            }
            await userManager.AddClaimAsync(usuario,new Claim(ClaimTypes.Role,userRol.RolName));
            await userManager.AddToRoleAsync(usuario,userRol.RolName);
            return Ok();
        }
        [HttpPost("RemoverUsuarioRol")]
        public async Task<ActionResult> RemoverRolUsuario([FromBody] UserRol userRol)
        {
            var usuario = await userManager.FindByIdAsync(userRol.UserId);
            if(usuario==null)
            {
                return NotFound();
            }
            await userManager.RemoveClaimAsync(usuario, new Claim(ClaimTypes.Role,userRol.RolName));
            await userManager.RemoveFromRoleAsync(usuario,userRol.RolName);
            return Ok();
        }
    }
}













