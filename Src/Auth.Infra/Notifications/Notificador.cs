
using Auth.Domain.Entities;
using Auth.Infra.Interfaces;

namespace Auth.Infra.Notifications;
public class Notificador : INotificador
{
    public List<Notificacao> _notificacoes;

    public Notificador()
    {
        _notificacoes = new List<Notificacao>();
    }

    public void Handle(Notificacao notificacao) => _notificacoes.Add(notificacao);

    public T? Handle<T>(string notificacao)
    {
        Handle(new Notificacao(notificacao));
        return default(T?);
    }

    public List<Notificacao> ObterNotificacoes() => _notificacoes;

    public bool TemNotificacao() =>
        _notificacoes.Any();
}
