import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, Lock } from "lucide-react";

export const Route = createFileRoute("/privacy")({
  component: Privacy,
});

const sections = [
  {
    title: "What Kedayam never sends anywhere",
    body: (
      <ul className="list-disc space-y-1 pl-5">
        <li>Browsing history</li>
        <li>Page contents (HTML, text, form values)</li>
        <li>Pasted or dropped data</li>
        <li>URLs you visit</li>
        <li>Detection results, verdicts, or scores</li>
        <li>Identifiers, cookies, or device fingerprints</li>
      </ul>
    ),
  },
  {
    title: "What Kedayam stores locally",
    body: (
      <>
        <p>
          Kedayam keeps a small amount of data in <code>chrome.storage.local</code>, which never
          leaves your browser and can be cleared any time from the extension&apos;s Options page:
        </p>
        <ul className="mt-3 list-disc space-y-1 pl-5">
          <li>User settings (sensitivity, allowlist, theme preference)</li>
          <li>A bounded cache of trust verdicts keyed by hostname (TTL-bound)</li>
          <li>An activity log of your own recent verdicts (never page content)</li>
          <li>Per-domain trust counters used to learn safe sites</li>
        </ul>
      </>
    ),
  },
  {
    title: "Clipboard scanning (ClickFix protection)",
    body: (
      <p>
        To stop "ClickFix" malware, Kedayam inspects text a web page writes to your clipboard to
        detect smuggled system commands. This check is purely in-memory and local: the page already
        possesses anything it copied, so nothing is exfiltrated. The clipboard text is classified
        and discarded — never stored, logged, or transmitted. Only a short, redacted preview appears
        in the warning prompt.
      </p>
    ),
  },
  {
    title: "Optional threat-feed refresh — off by default",
    body: (
      <p>
        You can opt in to refreshing the local blocklist from free public feeds (URLhaus, Phishing
        Army, OpenPhish). When enabled, Kedayam downloads the public feed files only — the request
        carries no information about you or the pages you visit. Matching against your actual URL
        still happens locally. This is disabled by default and can be turned off any time in
        Options.
      </p>
    ),
  },
  {
    title: "Optional third-party lookups",
    body: (
      <p>
        Kedayam can call Google Safe Browsing or VirusTotal only if you supply your own API key in
        Options. In that case, only the URL or a URL hash is sent for that lookup, and the third
        party's own privacy policy applies to that request. Both lookups are disabled out of the box
        — the default install makes zero outbound network requests.
      </p>
    ),
  },
  {
    title: "Sensitive-data scanning",
    body: (
      <p>
        When you paste, drop, or submit data, Kedayam runs an in-memory classifier to warn you
        before sensitive values leave the browser. The raw value is never persisted, logged, or
        transmitted, and findings are redacted before being shown to you.
      </p>
    ),
  },
  {
    title: "Diagnostics — off by default",
    body: (
      <p>
        A local-only debug buffer is available for development. It is off by default, held in memory
        only and wiped on extension restart, redacts URLs/tokens/emails before display, and is never
        written to storage or sent over the network.
      </p>
    ),
  },
  {
    title: "Permissions",
    body: (
      <p>
        Every permission Kedayam requests, and why, is documented in <code>PERMISSIONS.md</code> in
        the project repository.
      </p>
    ),
  },
  {
    title: "Contact",
    body: <p>Privacy questions can be raised by opening an issue on the project repository.</p>,
  },
];

function Privacy() {
  return (
    <main className="min-h-screen bg-background px-6 py-16 text-foreground md:px-10">
      <div className="mx-auto max-w-3xl">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm text-muted-foreground transition hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Back to Kedayam
        </Link>

        <div className="mt-8 flex items-center gap-3">
          <Lock className="h-7 w-7 text-cyber" aria-hidden="true" />
          <h1 className="text-3xl font-semibold tracking-normal md:text-4xl">Privacy Policy</h1>
        </div>
        <p className="mt-4 text-base leading-7 text-muted-foreground">
          Kedayam is a local-only browser security extension. It does not collect, transmit, sell,
          or share personal information. Kedayam contains no analytics SDK, no telemetry endpoint,
          and no background fetch to maintainer-controlled servers.
        </p>
        <p className="mt-3 text-sm text-muted-foreground">Last updated: 2026-07-29</p>

        <div className="mt-10 space-y-10 border-t border-border pt-10">
          {sections.map((section) => (
            <section key={section.title}>
              <h2 className="text-xl font-semibold tracking-normal">{section.title}</h2>
              <div className="mt-3 text-sm leading-7 text-muted-foreground">{section.body}</div>
            </section>
          ))}
        </div>
      </div>
    </main>
  );
}
