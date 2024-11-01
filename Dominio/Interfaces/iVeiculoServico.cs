using Microsoft.AspNetCore.Mvc.RazorPages;
using minimal_api.Migrations;
using MinimalApi.Dominio.Entidades;
using MinimalApi.DTOs;

namespace MinimalApi.Dominio.Interfaces;
public interface IVeiculoServico{
    List<Veiculo> Todos(int? pagina = 1, string? nome = null, string? marca=null, int? ano = null);
    Veiculo? BuscaPorId(int Id);
    void Incluir(Veiculo veiculo);
    void Atualizar(Veiculo veiculo);
    void Apagar(Veiculo veiculo);
}