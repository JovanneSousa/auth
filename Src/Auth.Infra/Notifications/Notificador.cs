
using Auth.Domain.Entities;
using Auth.Infra.Interfaces;

namespace Auth.Infra.Notifications;
/// <summary>
/// Componente responsável por centralizar e gerir notificações de erros de negócio durante o fluxo da requisição.
/// Utiliza o padrão Notification Pattern para evitar o lançamento de exceções para fluxos esperados.
/// </summary>
public class Notificador : INotificador
{
    public List<Notificacao> _notificacoes;

    public Notificador()
    {
        _notificacoes = new List<Notificacao>();
    }

    private void Handle(Notificacao notificacao) 
        => _notificacoes.Add(notificacao);

    public void Handle(string erro)
        => _notificacoes.Add(new Notificacao(erro));

    public T? Handle<T>(string notificacao)
    {
        Handle(new Notificacao(notificacao));
        return default(T?);
    }

    public List<Notificacao> ObterNotificacoes() => _notificacoes;

    public bool TemNotificacao() =>
        _notificacoes.Any();
}
