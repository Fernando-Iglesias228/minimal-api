using System.Runtime.CompilerServices;

namespace minimal_api.DTOs;

public record VeiculoDTO
{
    public required string Nome { get; set; }
    public required string Marca { get; set; }
    public int Ano { get; set; }
    
}