using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// What the two ANONYMOUS session surfaces may say. Everything about narrowing the status resource and
/// the SSE stream belongs here, including the fields deliberately left whole.
/// </summary>
/// <remarks>
/// Both surfaces ask for a session id and nothing else, and a session id is self-served by
/// <c>GET /verify/start</c>, so whoever can reach them can read whatever they return. These tests drive
/// real HTTP against the endpoints rather than calling <c>SessionView</c>, because the defect being
/// guarded against is a write path that forgets to narrow, and a test that calls the projection directly
/// cannot see a call site at all.
/// </remarks>
public sealed class AnonymousSurfaceDisclosureTests : IAsyncDisposable
{
    // The label the resolver AddTessioVerifier installs by default reports as its trust list. Written
    // out rather than read from the resolver so this test fails if that label changes, which is a
    // change to what the surface emits.
    private const string DevResolverSource = "tessio-dev-defaults";

    // A refusal reason a resolver wrote. Shaped like the locator the built-in loader reports, because
    // that is the string the narrowing exists to keep off this surface.
    private const string ResolverAuthoredLocator = "/srv/verification/anchors";

    private IHost? _host;

    private HttpClient StartHost(
        Action<VerifierOptions>? configure = null,
        Trust.ITrustListResolver? resolver = null)
    {
        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    // Before AddTessioVerifier, whose registration is TryAdd, so this one wins.
                    if (resolver is not null)
                    {
                        services.AddSingleton(resolver);
                    }

                    services.AddTessioVerifier(options =>
                    {
                        options.Mode = VerifierMode.Mock;
                        // Every test here posts a plaintext form, so the requests ask for a plaintext response. A
                        // callback in a mode its request did not ask for is refused before it can end the session.
                        options.ResponseMode = ResponseMode.DirectPost;
                        options.RequestedClaims = ["age_over_18"];
                        configure?.Invoke(options);
                    });
                })
                .Configure(app => app
                    .UseRouting()
                    .UseEndpoints(endpoints => endpoints.MapTessioVerifier())))
            .Start();
        return _host.GetTestClient();
    }

    /// <summary>
    /// Runs one mock presentation to a completed session and returns its id. The default resolver trusts
    /// the mock issuer, so the verdict is a pass unless the caller replaced the resolver.
    /// </summary>
    private async Task<string> CompleteSessionAsync(HttpClient client, bool expectTrusted = true)
    {
        var store = _host!.Services.GetRequiredService<InMemorySessionStore>();
        var options = _host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(
            options, new Uri("http://localhost/verify/callback")));

        var issuer = _host.Services.GetRequiredService<MockCredentialIssuer>();
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], DemoRequestOptionsFactory.DefaultVct, session.Request.Nonce, options.ClientId);
        var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["vp_token"] = $$"""{"credential":["{{presentation}}"]}""",
            ["state"] = session.Request.State!,
        });

        var callback = await client.PostAsync("/verify/callback", form);
        callback.EnsureSuccessStatusCode();

        // The verdict has to be the one the test wants, or a narrowing assertion passes because there
        // was nothing to narrow. A pass with no source, or a refusal that reached no resolver, would
        // both make these tests green for the wrong reason.
        var completed = await store.GetAsync(session.SessionId);
        Assert.Equal(expectTrusted, completed!.Result!.Issuer.Trusted);
        Assert.NotNull(completed.Result.Issuer.TrustListSource);
        if (expectTrusted)
        {
            Assert.Equal(DevResolverSource, completed.Result.Issuer.TrustListSource);
        }
        else
        {
            // The CONTROL for every narrowing assertion below: the real message and the real locator are
            // in the store, so an assertion that the surface shows the token is measuring a replacement
            // rather than an absence. It lives here, not in a test of its own, because the projection
            // cannot write back at all: every field on the path is init-only and the store's first write
            // wins, so a standalone test of it would be one that cannot fail.
            Assert.NotEmpty(completed.Result.Errors);
            Assert.NotEqual(VerifierOptions.UndisclosedErrorMessage, completed.Result.Errors[0].Message);
            Assert.Equal(ResolverAuthoredLocator, completed.Result.Issuer.TrustListSource);
        }

        return session.SessionId;
    }

    private static string? SourceIn(JsonElement view) =>
        view.GetProperty("result").GetProperty("issuer").GetProperty("trustListSource").GetString();

    [Fact]
    public async Task Status_SourceNotOnTheAllowlist_IsReplacedByTheToken()
    {
        var client = StartHost();
        var sessionId = await CompleteSessionAsync(client);

        var view = await client.GetFromJsonAsync<JsonElement>($"/verify/{sessionId}");

        Assert.Equal(VerifierOptions.UndisclosedTrustListSource, SourceIn(view));
    }

    [Fact]
    public async Task Status_SourceOnTheAllowlist_IsEmittedWhole()
    {
        var client = StartHost(options => options.PublicTrustListSources.Add(DevResolverSource));
        var sessionId = await CompleteSessionAsync(client);

        var view = await client.GetFromJsonAsync<JsonElement>($"/verify/{sessionId}");

        Assert.Equal(DevResolverSource, SourceIn(view));
    }

    [Fact]
    public async Task Status_AllowlistMatchesOnExactBytes_NotOnCase()
    {
        var client = StartHost(options => options.PublicTrustListSources.Add(DevResolverSource.ToUpperInvariant()));
        var sessionId = await CompleteSessionAsync(client);

        var view = await client.GetFromJsonAsync<JsonElement>($"/verify/{sessionId}");

        // A locator is a URL or a path. Neither is case-insensitive in general, and a comparer that
        // folded case would let a near-miss entry disclose a value the deployment never listed.
        Assert.Equal(VerifierOptions.UndisclosedTrustListSource, SourceIn(view));
    }

    [Fact]
    public async Task Stream_NarrowsTheSameWayAsTheStatusResource()
    {
        var client = StartHost();
        var sessionId = await CompleteSessionAsync(client);

        var body = await client.GetStringAsync($"/verify/{sessionId}/stream");

        Assert.Contains($"\"trustListSource\":\"{VerifierOptions.UndisclosedTrustListSource}\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain(DevResolverSource, body, StringComparison.Ordinal);
    }

    /// <summary>
    /// A session completed with a result whose nested <see cref="Core.VerificationResult.VerifiedPresentations"/>
    /// carry a locator and a free text message of their own, written to the store directly so that the nested values
    /// are known to be there and anything the surface shows of them is the narrowing's doing.
    /// </summary>
    private async Task<string> CompleteWithNestedResultsAsync()
    {
        var store = _host!.Services.GetRequiredService<InMemorySessionStore>();
        var options = _host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(options, new Uri("http://localhost/verify/callback")));

        var issuer = new Core.IssuerInfo
        {
            Identifier = "https://issuer.example",
            Trusted = true,
            KeyResolutionMethod = "x5c",
            TrustListSource = ResolverAuthoredLocator,
        };
        var nested = Core.VerificationResult.Valid(new Dictionary<string, object> { ["age_over_18"] = true }, issuer) with
        {
            Errors = [new Core.VerificationError { Code = "example", Message = ResolverAuthoredLocator }],
        };
        var top = Core.VerificationResult.Valid(new Dictionary<string, object>(), issuer) with { VerifiedPresentations = [nested] };
        await store.CompleteAsync(session.SessionId, top);
        return session.SessionId;
    }

    [Fact]
    public async Task Status_NarrowsEveryNestedVerifiedPresentation_TooNotOnlyTheTopLevelResult()
    {
        var client = StartHost();
        var sessionId = await CompleteWithNestedResultsAsync();

        var body = await client.GetStringAsync($"/verify/{sessionId}");
        var nested = JsonDocument.Parse(body).RootElement.GetProperty("result").GetProperty("verifiedPresentations")[0];

        Assert.Equal(VerifierOptions.UndisclosedTrustListSource, nested.GetProperty("issuer").GetProperty("trustListSource").GetString());
        Assert.Equal(VerifierOptions.UndisclosedErrorMessage, nested.GetProperty("errors")[0].GetProperty("message").GetString());
        Assert.DoesNotContain(ResolverAuthoredLocator, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Stream_NarrowsEveryNestedVerifiedPresentation_Too()
    {
        var client = StartHost();
        var sessionId = await CompleteWithNestedResultsAsync();

        var body = await client.GetStringAsync($"/verify/{sessionId}/stream");

        Assert.Contains("verifiedPresentations", body, StringComparison.Ordinal);
        Assert.DoesNotContain(ResolverAuthoredLocator, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Status_CarriesANestedClaimAtTheDepthBound()
    {
        // SdJwtVcVerifier refuses a claim deeper than JsonValueConverter.MaxDepth, so this is the deepest a nested
        // verified presentation can carry. It serializes with room to spare under the serializer's depth limit.
        var client = StartHost();
        var store = _host!.Services.GetRequiredService<InMemorySessionStore>();
        var options = _host.Services.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var session = await store.CreateAsync(DemoRequestOptionsFactory.Create(options, new Uri("http://localhost/verify/callback")));
        object deep = 1L;
        // JsonValueConverter.MaxDepth, internal to the core package; its own tests pin the bound at this value.
        for (var i = 0; i < 32; i++)
        {
            deep = new Dictionary<string, object> { ["a"] = deep };
        }

        var nested = Core.VerificationResult.Valid(new Dictionary<string, object> { ["deep"] = deep }, Core.IssuerInfo.Unknown);
        await store.CompleteAsync(session.SessionId, nested with { VerifiedPresentations = [nested] });

        var response = await client.GetAsync($"/verify/{session.SessionId}");

        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Status_AnchorProvenance_IsNotNarrowed()
    {
        var client = StartHost();
        var sessionId = await CompleteSessionAsync(client);

        var view = await client.GetFromJsonAsync<JsonElement>($"/verify/{sessionId}");

        // The caller's own credential produced these, so they name the one anchor that caller has just
        // proved it chains to, rather than the set the deployment holds. This pins the decision: if a
        // later change narrows these too, it is a deliberate change and not a drift.
        var issuer = view.GetProperty("result").GetProperty("issuer");
        Assert.False(string.IsNullOrEmpty(issuer.GetProperty("trustAnchorSubject").GetString()));
        Assert.False(string.IsNullOrEmpty(issuer.GetProperty("trustAnchorThumbprint").GetString()));
    }

    [Fact]
    public async Task Status_FailureMessage_IsReplaced_AndTheCodeSurvives()
    {
        // A resolver that names its list in the reason, which is what the seam's own documentation
        // invites and what the built-in status list checks already do with a URL and an inner exception.
        var client = StartHost(resolver: new Trust.StaticTrustListResolver([], source: ResolverAuthoredLocator));
        var sessionId = await CompleteSessionAsync(client, expectTrusted: false);

        var view = await client.GetFromJsonAsync<JsonElement>($"/verify/{sessionId}");

        var error = view.GetProperty("result").GetProperty("errors")[0];
        Assert.Equal("issuer_untrusted", error.GetProperty("code").GetString());
        Assert.Equal(VerifierOptions.UndisclosedErrorMessage, error.GetProperty("message").GetString());
    }

    [Fact]
    public async Task Stream_ReplacesTheFailureMessageToo()
    {
        var client = StartHost(resolver: new Trust.StaticTrustListResolver([], source: ResolverAuthoredLocator));
        var sessionId = await CompleteSessionAsync(client, expectTrusted: false);

        var body = await client.GetStringAsync($"/verify/{sessionId}/stream");

        // Assert the replacement is PRESENT, not merely that the locator is absent. The refusal this
        // resolver produces does not put its source in the reason text, so an absence assertion here
        // stayed green with the message narrowing deleted: it was measuring the other protection.
        Assert.Contains(VerifierOptions.UndisclosedErrorMessage, body, StringComparison.Ordinal);
        Assert.Contains("issuer_untrusted", body, StringComparison.Ordinal);
    }


    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
    }
}
