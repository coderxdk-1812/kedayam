// Compatibility — high-mutation real-world apps must not produce duplicate
// dangerous verdicts or excessive rescans. We simulate the structural facts
// the content script would extract from each app.
import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const REAL_WORLD_PAGES = [
  {
    url: "https://mail.google.com/mail/u/0/#inbox",
    ctx: {
      pageOrigin: "https://mail.google.com",
      title: "Inbox - alice@gmail.com - Gmail",
      visibleText: "Inbox starred sent drafts",
      forms: [],
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      hasPasswordField: false,
    },
    expect: ["safe"],
  },
  {
    url: "https://docs.google.com/document/d/abc/edit",
    ctx: {
      pageOrigin: "https://docs.google.com",
      title: "Untitled document",
      visibleText: "Type to start",
      forms: [],
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      hasPasswordField: false,
    },
    expect: ["safe"],
  },
  {
    url: "https://app.slack.com/client/T01/C01",
    ctx: {
      pageOrigin: "https://app.slack.com",
      title: "Slack | general",
      visibleText: "general channel",
      forms: [],
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      hasPasswordField: false,
    },
    expect: ["safe"],
  },
  {
    url: "https://www.notion.so/Project-abc",
    ctx: {
      pageOrigin: "https://www.notion.so",
      title: "Project · Notion",
      visibleText: "Project notes",
      forms: [],
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      hasPasswordField: false,
    },
    expect: ["safe"],
  },
  {
    url: "https://github.com/user/repo",
    ctx: {
      pageOrigin: "https://github.com",
      title: "user/repo",
      visibleText: "README files commits",
      forms: [],
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      hasPasswordField: false,
    },
    expect: ["safe"],
  },
  {
    url: "https://www.figma.com/files/recent",
    ctx: {
      pageOrigin: "https://www.figma.com",
      title: "Recent files - Figma",
      visibleText: "Recent files",
      forms: [],
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      hasPasswordField: false,
    },
    expect: ["safe"],
  },
  {
    url: "https://discord.com/channels/@me",
    ctx: {
      pageOrigin: "https://discord.com",
      title: "Discord",
      visibleText: "Friends online",
      forms: [],
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      hasPasswordField: false,
    },
    expect: ["safe", "suspicious"],
  },
  {
    url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    ctx: {
      pageOrigin: "https://login.microsoftonline.com",
      title: "Sign in to your account",
      visibleText: "Sign in Use your Microsoft account",
      forms: [
        { hasPassword: false, hasEmailLike: true, hasOtp: false, hiddenCount: 4, fieldsCount: 6 },
      ],
      hasPasswordField: false,
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
      firstFieldKind: "email",
      hasLogoImage: true,
      hasHeading: true,
    },
    expect: ["safe", "suspicious"],
  },
];

describe("compatibility — real-world apps must not get dangerous verdict", () => {
  for (const page of REAL_WORLD_PAGES) {
    it(`${new URL(page.url).host} → ${page.expect.join("|")}`, async () => {
      const verdict = await evaluateUrl(page.url, {
        settings: { detection: { sensitivity: "balanced" } },
        pageContext: page.ctx,
      });
      expect(page.expect).toContain(verdict.status);
      // Never dangerous on these hosts.
      expect(verdict.status).not.toBe("dangerous");
    });
  }
});
