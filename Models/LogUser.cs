#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
namespace LoginReg.Models;

public class LogUser
{
    // No other fields!
    [Required]
    [EmailAddress]
    [Display (Name="Email")]
    public string LogEmail { get; set; }    

    [Required]
    [DataType(DataType.Password)]
    [Display(Name="Password")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
    public string LogPassword { get; set; }  
}