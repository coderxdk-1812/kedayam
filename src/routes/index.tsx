import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  Chrome,
  Download,
  EyeOff,
  FolderOpen,
  Github,
  KeyRound,
  Lock,
  MousePointer2,
  Radar,
  ScanLine,
  Settings,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";

export const Route = createFileRoute("/")({
  component: Index,
});

const fadeUp = {
  initial: { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-80px" },
  transition: { duration: 0.45, ease: [0.16, 1, 0.3, 1] as [number, number, number, number] },
};

function Index() {
  const download = () => {
    fetch("/kedayam.zip")
      .then((response) => {
        if (!response.ok) throw new Error(`Download failed: ${response.status}`);
        return response.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = "kedayam.zip";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 500);
      })
      .catch((err) => alert(err.message));
  };

  const features = [
    { icon: ShieldCheck, title: "Phishing protection", copy: "Scores risky pages before credentials or personal data are exposed." },
    { icon: KeyRound, title: "Sensitive data detection", copy: "Finds PII, payment cards, API tokens, JWTs, and private keys locally." },
    { icon: UploadCloud, title: "Upload scanning", copy: "Reviews text-based files before they leave the browser." },
    { icon: Lock, title: "Permission monitoring", copy: "Adds calm context when low-trust pages request camera, mic, or location." },
    { icon: EyeOff, title: "Clone website detection", copy: "Flags lookalike domains, homoglyph tricks, and suspicious URL shapes." },
    { icon: Radar, title: "Real-time trust scoring", copy: "Shows an explainable 0–100 verdict from local and reputation signals." },
  ];

  const flow = [
    { icon: MousePointer2, title: "User browses", copy: "Kedayam quietly observes page navigations and sensitive actions." },
    { icon: ScanLine, title: "Scans locally", copy: "Pastes, uploads, URL shape, and browser signals are analyzed on-device." },
    { icon: Radar, title: "Threats analyzed", copy: "Reputation APIs are only used for domain intelligence when configured." },
    { icon: ShieldCheck, title: "Warns before danger", copy: "Low risk stays passive. Medium is concise. High risk requires intent." },
  ];

  const installSteps = [
    { icon: Download, title: "Download extension", copy: "Save kedayam.zip, then unzip it into a folder you can find again." },
    { icon: Chrome, title: "Open extensions", copy: "Go to chrome://extensions in Chrome, Edge, Brave, Arc, or Opera." },
    { icon: Settings, title: "Enable Developer Mode", copy: "Turn on the Developer mode toggle in the top-right corner." },
    { icon: UploadCloud, title: "Load Unpacked", copy: "Click Load unpacked from the toolbar at the top of the page." },
    { icon: FolderOpen, title: "Select build folder", copy: "Choose the unzipped Kedayam folder that contains manifest.json." },
    { icon: CheckCircle2, title: "Kedayam activates", copy: "Pin the shield to your toolbar and open any site to see a trust score." },
  ];

  const troubleshooting = [
    {
      issue: "Could not load manifest",
      fix: "Select the unzipped extension folder itself, not the parent folder or the ZIP file. The selected folder must contain manifest.json at its top level.",
    },
    {
      issue: "Missing icon errors",
      fix: "Kedayam now ships PNG icon16, icon32, icon48, and icon128 files inside the extension package. Rebuild with bun run build:extension if files are missing.",
    },
    {
      issue: "Permission issues",
      fix: "Refresh the page after installing. Browser protections only run on http and https pages, not internal chrome:// pages.",
    },
    {
      issue: "Service worker issues",
      fix: "Open chrome://extensions, click Kedayam details, then Service worker. Use Reload after rebuilding the extension package.",
    },
  ];

  return (
    <main className="min-h-screen overflow-hidden bg-background text-foreground">
      <section className="relative min-h-[92vh] px-6 py-6 md:px-10">
        <motion.div
          aria-hidden="true"
          className="absolute inset-0 opacity-70"
          animate={{ backgroundPosition: ["0% 0%", "100% 100%"] }}
          transition={{ duration: 18, repeat: Infinity, repeatType: "reverse", ease: "linear" }}
          style={{
            background:
              "radial-gradient(circle at 78% 8%, color-mix(in oklab, var(--cyber) 18%, transparent), transparent 34%), radial-gradient(circle at 12% 78%, color-mix(in oklab, var(--primary) 12%, transparent), transparent 30%)",
            backgroundSize: "140% 140%",
          }}
        />
        <div aria-hidden="true" className="absolute inset-0 bg-[linear-gradient(to_right,color-mix(in_oklab,var(--border)_42%,transparent)_1px,transparent_1px),linear-gradient(to_bottom,color-mix(in_oklab,var(--border)_42%,transparent)_1px,transparent_1px)] bg-[size:72px_72px] opacity-20" />

        <header className="relative z-10 mx-auto flex max-w-7xl items-center justify-between py-2">
          <a href="#top" className="flex items-center gap-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background">
            <img src="/icons/icon48.png" alt="Kedayam shield logo" className="h-10 w-10" />
            <div>
              <div className="text-sm font-semibold tracking-wide">Kedayam</div>
              <div className="text-[0.65rem] uppercase tracking-[0.28em] text-muted-foreground">Browser shield</div>
            </div>
          </a>
          <button
            onClick={download}
            className="inline-flex items-center gap-2 rounded-lg bg-cyber px-4 py-2 text-sm font-semibold text-cyber-foreground shadow-sm transition hover:-translate-y-0.5 hover:opacity-95 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
          >
            <Download className="h-4 w-4" aria-hidden="true" />
            Install
          </button>
        </header>

        <div id="top" className="relative z-10 mx-auto grid max-w-7xl gap-14 pb-16 pt-20 md:pt-28 lg:grid-cols-[1.02fr_0.98fr] lg:items-center">
          <motion.div {...fadeUp}>
            <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium uppercase tracking-[0.22em] text-cyber backdrop-blur-xl">
              <span className="h-1.5 w-1.5 rounded-full bg-safe" aria-hidden="true" />
              Privacy-first protection
            </div>
            <h1 className="max-w-3xl text-5xl font-semibold leading-[1.02] tracking-normal text-foreground md:text-7xl">
              Kedayam
            </h1>
            <p className="mt-5 max-w-2xl text-2xl font-medium text-foreground md:text-3xl">
              Protect your browsing in real time.
            </p>
            <p className="mt-5 max-w-xl text-base leading-8 text-muted-foreground md:text-lg">
              A calm Chrome security extension that detects phishing risk, sensitive-data leaks, suspicious uploads, and permission abuse before damage happens.
            </p>
            <div className="mt-10 flex flex-col gap-3 sm:flex-row">
              <button
                onClick={download}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyber px-6 py-3 text-sm font-semibold text-cyber-foreground shadow-lg shadow-cyber/10 transition hover:-translate-y-0.5 hover:opacity-95 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
              >
                <Download className="h-4 w-4" aria-hidden="true" />
                Download Kedayam
              </button>
              <a
                href="#install"
                className="inline-flex items-center justify-center rounded-xl border border-border bg-surface px-6 py-3 text-sm font-semibold text-foreground backdrop-blur-xl transition hover:-translate-y-0.5 hover:bg-accent focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
              >
                View install steps
              </a>
            </div>
            <p className="mt-4 text-sm text-muted-foreground">Manifest V3 · Chrome, Edge, Brave, Arc, Opera · v1.0.0</p>
          </motion.div>

          <motion.div {...fadeUp} transition={{ duration: 0.5, delay: 0.08 }} className="relative">
            <div className="rounded-3xl border border-border bg-surface p-5 shadow-2xl shadow-background/60 backdrop-blur-2xl md:p-7">
              <div className="flex items-center justify-between gap-4 border-b border-border pb-5">
                <div className="flex items-center gap-3">
                  <img src="/icons/icon48.png" alt="Kedayam shield logo" className="h-11 w-11" />
                  <div>
                    <div className="font-semibold">Live trust score</div>
                    <div className="text-sm text-muted-foreground">secure.example.com</div>
                  </div>
                </div>
                <span className="rounded-full border border-border bg-background/50 px-3 py-1 text-xs font-medium text-safe">Protected</span>
              </div>

              <div className="grid gap-7 py-8 sm:grid-cols-[180px_1fr] sm:items-center">
                <div className="relative mx-auto grid h-44 w-44 place-items-center rounded-full text-safe">
                  <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-hidden="true">
                    <circle cx="60" cy="60" r="52" fill="none" stroke="currentColor" strokeOpacity="0.13" strokeWidth="8" />
                    <motion.circle
                      cx="60"
                      cy="60"
                      r="52"
                      fill="none"
                      stroke="currentColor"
                      strokeLinecap="round"
                      strokeWidth="8"
                      strokeDasharray="326.7"
                      initial={{ strokeDashoffset: 326.7 }}
                      animate={{ strokeDashoffset: 29.4 }}
                      transition={{ duration: 1.2, ease: "easeOut" }}
                    />
                  </svg>
                  <div className="absolute text-center">
                    <div className="text-5xl font-semibold tracking-normal text-foreground">91</div>
                    <div className="text-xs uppercase tracking-[0.24em] text-safe">Safe</div>
                  </div>
                </div>
                <div className="space-y-3">
                  {[
                    "Encrypted connection verified",
                    "No lookalike domain signals",
                    "No sensitive paste detected",
                    "Permissions are quiet",
                  ].map((signal) => (
                    <div key={signal} className="flex items-center gap-3 rounded-2xl border border-border bg-background/35 px-4 py-3 text-sm">
                      <CheckCircle2 className="h-4 w-4 text-safe" aria-hidden="true" />
                      <span>{signal}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      <section className="px-6 py-20 md:px-10" aria-labelledby="features-title">
        <div className="mx-auto max-w-7xl">
          <motion.div {...fadeUp} className="max-w-2xl">
            <p className="text-sm font-semibold uppercase tracking-[0.22em] text-cyber">Capabilities</p>
            <h2 id="features-title" className="mt-3 text-3xl font-semibold tracking-normal md:text-5xl">Security that stays out of the way.</h2>
          </motion.div>
          <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {features.map((feature) => (
              <motion.article
                key={feature.title}
                {...fadeUp}
                className="group rounded-2xl border border-border bg-surface p-6 backdrop-blur-xl transition hover:-translate-y-1 hover:bg-accent/60"
              >
                <feature.icon className="h-6 w-6 text-cyber transition group-hover:scale-105" aria-hidden="true" />
                <h3 className="mt-6 text-lg font-semibold">{feature.title}</h3>
                <p className="mt-3 text-sm leading-7 text-muted-foreground">{feature.copy}</p>
              </motion.article>
            ))}
          </div>
        </div>
      </section>

      <section className="border-y border-border bg-surface/40 px-6 py-20 md:px-10" aria-labelledby="flow-title">
        <div className="mx-auto max-w-7xl">
          <motion.div {...fadeUp} className="grid gap-10 lg:grid-cols-[0.75fr_1.25fr] lg:items-start">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.22em] text-cyber">How it works</p>
              <h2 id="flow-title" className="mt-3 text-3xl font-semibold tracking-normal md:text-5xl">Private by default. Clear when it matters.</h2>
              <p className="mt-5 text-base leading-8 text-muted-foreground">Kedayam prioritizes local scanning, quiet context, and proportionate warnings instead of constant interruptions.</p>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {flow.map((item, index) => (
                <div key={item.title} className="rounded-2xl border border-border bg-background/45 p-6">
                  <div className="flex items-center justify-between">
                    <item.icon className="h-5 w-5 text-cyber" aria-hidden="true" />
                    <span className="text-sm text-muted-foreground">0{index + 1}</span>
                  </div>
                  <h3 className="mt-6 font-semibold">{item.title}</h3>
                  <p className="mt-2 text-sm leading-7 text-muted-foreground">{item.copy}</p>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      <section id="install" className="px-6 py-20 md:px-10" aria-labelledby="install-title">
        <div className="mx-auto max-w-7xl">
          <motion.div {...fadeUp} className="flex flex-col justify-between gap-6 md:flex-row md:items-end">
            <div className="max-w-2xl">
              <p className="text-sm font-semibold uppercase tracking-[0.22em] text-cyber">Installation</p>
              <h2 id="install-title" className="mt-3 text-3xl font-semibold tracking-normal md:text-5xl">Install in a few deliberate steps.</h2>
            </div>
            <button
              onClick={download}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyber px-5 py-3 text-sm font-semibold text-cyber-foreground transition hover:-translate-y-0.5 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
            >
              <Download className="h-4 w-4" aria-hidden="true" />
              Download ZIP
            </button>
          </motion.div>

          <div className="mt-12 grid gap-4 lg:grid-cols-3">
            {installSteps.map((step, index) => (
              <motion.article key={step.title} {...fadeUp} className="rounded-2xl border border-border bg-surface p-5 backdrop-blur-xl">
                <div className="flex items-start justify-between gap-4">
                  <div className="grid h-11 w-11 place-items-center rounded-xl bg-background/60 text-cyber">
                    <step.icon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <span className="text-sm font-semibold text-muted-foreground">Step {index + 1}</span>
                </div>
                <h3 className="mt-5 font-semibold">{step.title}</h3>
                <p className="mt-2 text-sm leading-7 text-muted-foreground">{step.copy}</p>
              </motion.article>
            ))}
          </div>
        </div>
      </section>

      <section className="px-6 pb-20 md:px-10" aria-labelledby="troubleshooting-title">
        <div className="mx-auto grid max-w-7xl gap-8 lg:grid-cols-[0.75fr_1.25fr]">
          <motion.div {...fadeUp}>
            <p className="text-sm font-semibold uppercase tracking-[0.22em] text-cyber">Troubleshooting</p>
            <h2 id="troubleshooting-title" className="mt-3 text-3xl font-semibold tracking-normal md:text-5xl">Clean reloads, clear fixes.</h2>
            <p className="mt-5 text-base leading-8 text-muted-foreground">The install package validates manifest paths, PNG icons, popup files, options files, content scripts, and service worker references before it ships.</p>
          </motion.div>
          <motion.div {...fadeUp} className="space-y-3">
            {troubleshooting.map((item) => (
              <details key={item.issue} className="group rounded-2xl border border-border bg-surface p-5 backdrop-blur-xl">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-semibold focus:outline-none focus:ring-2 focus:ring-ring">
                  <span className="inline-flex items-center gap-3"><AlertTriangle className="h-4 w-4 text-warning" aria-hidden="true" />{item.issue}</span>
                  <ChevronDown className="h-4 w-4 text-muted-foreground transition group-open:rotate-180" aria-hidden="true" />
                </summary>
                <p className="mt-4 text-sm leading-7 text-muted-foreground">{item.fix}</p>
              </details>
            ))}
          </motion.div>
        </div>
      </section>

      <section className="border-y border-border bg-surface/40 px-6 py-20 md:px-10" aria-labelledby="privacy-title">
        <motion.div {...fadeUp} className="mx-auto max-w-7xl rounded-3xl border border-border bg-background/45 p-7 backdrop-blur-xl md:p-10">
          <div className="grid gap-10 lg:grid-cols-[0.8fr_1.2fr] lg:items-start">
            <div>
              <Lock className="h-7 w-7 text-cyber" aria-hidden="true" />
              <h2 id="privacy-title" className="mt-5 text-3xl font-semibold tracking-normal md:text-5xl">Security and privacy, stated plainly.</h2>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                "All sensitive scans happen locally.",
                "Sensitive inputs are never uploaded.",
                "APIs are only used for domain reputation.",
                "No password storage.",
                "No tracking by default.",
                "No selling data.",
              ].map((item) => (
                <div key={item} className="flex gap-3 rounded-2xl border border-border bg-surface p-4 text-sm">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-safe" aria-hidden="true" />
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </section>

      <footer className="px-6 py-10 md:px-10">
        <div className="mx-auto flex max-w-7xl flex-col gap-5 text-sm text-muted-foreground md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <img src="/icons/icon32.png" alt="Kedayam shield logo" className="h-8 w-8" />
            <span>Kedayam v1.0.0 · Privacy-first browser security</span>
          </div>
          <div className="flex gap-5">
            <a className="inline-flex items-center gap-2 transition hover:text-foreground" href="https://github.com" target="_blank" rel="noreferrer"><Github className="h-4 w-4" aria-hidden="true" />GitHub</a>
            <a className="inline-flex items-center gap-2 transition hover:text-foreground" href="#install"><BookOpen className="h-4 w-4" aria-hidden="true" />Documentation</a>
          </div>
        </div>
      </footer>
    </main>
  );
}
