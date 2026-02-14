using auth.Src.Domain.Entities;
using auth.Src.Domain.Interfaces;

namespace auth.Src.Infra.Notifications;

public class Notificador : INotificador
{
    public List<Notificacao> _notificacoes;

    public Notificador()
    {
        _notificacoes = new List<Notificacao>();
    }

    public void Handle(Notificacao notificacao) => _notificacoes.Add(notificacao);

    public List<Notificacao> ObterNotificacoes() => _notificacoes;

    public bool TemNotificacao() =>
        _notificacoes.Any();
}
