using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// JSON-friendly projection of a <see cref="VerificationSession"/> for the status endpoint and SSE stream.
/// Deliberately excludes the authorization request, in every form.
/// </summary>
/// <remarks>
/// <b>This is an ANONYMOUS surface, so it is where disclosure is decided.</b> A session id is self-served
/// by <c>GET {prefix}/start</c> and is the only thing the status endpoint asks for, so anything reachable
/// from here is reachable by anyone. The projection therefore narrows what the verification result says
/// rather than passing it through: every free-text failure message, and the trust list identifier unless
/// the deployment published it. See <see cref="VerifierOptions.PublicTrustListSources"/> for why that
/// second one is an allowlist and not a rule about which strings look risky.
/// <para>
/// <b>The authorization request is not here, and must not come back.</b> A wallet's callback is matched
/// to its session by <c>state</c>, so <c>state</c> stays off anything keyed only by a session id. The
/// authorization request URI leads to <c>state</c> in both delivery modes, embedded in the request
/// object by value or one anonymous fetch of <c>request_uri</c> away by reference. It belongs only where
/// it is needed: the start page shows it to the user about to hand it to a wallet, and the wallet fetches
/// the request object.
/// </para>
/// </remarks>
internal sealed record SessionView
{
    public required string SessionId { get; init; }

    public required string Status { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    public VerificationResult? Result { get; init; }

    /// <summary>
    /// The latest failed attempt while the session stays pending, narrowed exactly as <see cref="Result"/>
    /// is. Null until a failed attempt is recorded, which the built-in callback does only with
    /// <see cref="VerifierOptions.CompleteOnlyOnValidResponse"/> on.
    /// </summary>
    public VerificationResult? LastFailure { get; init; }

    public int FailedAttempts { get; init; }

    /// <summary>Projects a session for an anonymous caller.</summary>
    /// <param name="session">The session to project.</param>
    /// <param name="publicTrustListSources">
    /// Trust list identifiers the deployment has declared safe for an anonymous caller. Anything else is
    /// replaced by <see cref="VerifierOptions.UndisclosedTrustListSource"/>. Pass an empty set to disclose
    /// none, which is the default.
    /// </param>
    public static SessionView From(VerificationSession session, ISet<string> publicTrustListSources) => new()
    {
        SessionId = session.SessionId,
        Status = session.Status.ToString().ToLowerInvariant(),
        ExpiresAt = session.ExpiresAt,
        Result = Narrow(session.Result, publicTrustListSources),
        LastFailure = Narrow(session.LastFailure, publicTrustListSources),
        FailedAttempts = session.FailedAttempts,
    };

    /// <summary>
    /// The result as an anonymous caller may see it: no free-text failure message, and the trust list
    /// named only where the deployment said it may be.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every free-text string goes, not the ones that look risky.</b> A failure message is written by
    /// whoever produced the failure: <see cref="Core.VerificationError.Code"/> is the stable part a
    /// caller acts on, and the message is prose that has already been observed to carry a locator. The
    /// built-in status list checks interpolate a URL and an inner exception message, and an
    /// <c>ITrustListResolver</c> is free to name its list in a reason. Keeping the codes and dropping
    /// the messages needs no judgement about any individual string.
    /// </para>
    /// <para>
    /// The anchor subject and thumbprint are left alone deliberately. The caller's own credential is
    /// what produced them, so they name the one anchor that caller already proved it chains to, rather
    /// than the set the deployment holds.
    /// </para>
    /// </remarks>
    private static VerificationResult? Narrow(VerificationResult? result, ISet<string> publicTrustListSources)
    {
        if (result is null)
        {
            return null;
        }

        var source = result.Issuer.TrustListSource;
        var narrowed = source is null || publicTrustListSources.Contains(source)
            ? result
            : result with
            {
                Issuer = result.Issuer with { TrustListSource = VerifierOptions.UndisclosedTrustListSource },
            };

        // Every nested result is a result like this one and goes out beside it, so it is narrowed by the same
        // rules. Each carries its own issuer, and so its own trust list source.
        if (narrowed.VerifiedPresentations is { } presentations)
        {
            narrowed = narrowed with
            {
                VerifiedPresentations = [.. presentations.Select(p => Narrow(p, publicTrustListSources)!)],
            };
        }

        // Read from narrowed, not from result. They hold the same errors today, and a later narrowing
        // that touched them first would silently lose its work if this went back to the original.
        return narrowed.Errors.Count == 0
            ? narrowed
            : narrowed with
            {
                Errors = [.. narrowed.Errors.Select(e => new VerificationError
                {
                    Code = e.Code,
                    Message = VerifierOptions.UndisclosedErrorMessage,
                })],
            };
    }
}
