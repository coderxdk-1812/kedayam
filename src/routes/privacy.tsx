import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/privacy")({
  head: () => ({
    meta: [
      { title: "Privacy Policy — Kedayam" },
      { name: "description", content: "Kedayam privacy policy and data practices." },
      { property: "og:title", content: "Privacy Policy — Kedayam" },
      { property: "og:description", content: "Kedayam privacy policy and data practices." },
    ],
  }),
  component: PrivacyPage,
});

function PrivacyPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-12">
      <h1 className="text-3xl font-bold tracking-tight text-foreground">
        Privacy Policy
      </h1>
      <p className="mt-4 text-muted-foreground">
        Kedayam is built with a privacy-first architecture. This policy explains what data we handle and how we protect it.
      </p>

      <section className="mt-10 space-y-6">
        <div>
          <h2 className="text-xl font-semibold text-foreground">Local-First Processing</h2>
          <p className="mt-2 text-muted-foreground">
            All phishing detection, sensitive data scanning, and threat analysis happen locally in your browser. No browsing history, page content, or credentials are sent to external servers.
          </p>
        </div>

        <div>
          <h2 className="text-xl font-semibold text-foreground">Data We Do Not Collect</h2>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-muted-foreground">
            <li>Websites you visit</li>
            <li>Passwords, credit cards, or personal data</li>
            <li>Form inputs or keystrokes</li>
            <li>Browser history</li>
          </ul>
        </div>

        <div>
          <h2 className="text-xl font-semibold text-foreground">Optional Cloud Features</h2>
          <p className="mt-2 text-muted-foreground">
            If you enable remote sync or reporting, only anonymized threat signatures (not URLs or content) are transmitted. You can disable this at any time.
          </p>
        </div>

        <div>
          <h2 className="text-xl font-semibold text-foreground">Permissions</h2>
          <p className="mt-2 text-muted-foreground">
            Kedayam requests the minimum permissions necessary for active tab monitoring and script injection. No permissions are used for tracking or advertising.
          </p>
        </div>

        <div>
          <h2 className="text-xl font-semibold text-foreground">Contact</h2>
          <p className="mt-2 text-muted-foreground">
            Questions about privacy can be directed through the extension support channel.
          </p>
        </div>
      </section>
    </div>
  );
}
