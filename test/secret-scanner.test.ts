import { describe, it, expect } from "vitest";
import { scanSecrets, shannonEntropy } from "../src/analyzers/secret-scanner.js";
import type { ContextSnapshot, FileInfo } from "../src/types.js";

function makeSnapshot(overrides: Partial<ContextSnapshot> = {}): ContextSnapshot {
  return {
    timestamp: Date.now(),
    activeFile: null,
    selection: null,
    openTabs: [],
    referencedFiles: [],
    terminalContent: null,
    clipboardSize: null,
    chatHistoryLength: 0,
    aiInstructionFiles: [],
    toolProfile: null,
    ignoreFiles: [],
    ...overrides,
  };
}

function makeFile(overrides: Partial<FileInfo> = {}): FileInfo {
  return {
    path: "src/config.ts",
    languageId: "typescript",
    lineCount: 50,
    charCount: 2000,
    isActive: true,
    isDirty: false,
    commentLineCount: 0,
    hasConflictMarkers: false,
    ...overrides,
  };
}

function langFromPath(path: string): string {
  if (path.endsWith(".yml") || path.endsWith(".yaml")) return "yaml";
  if (path.endsWith(".properties")) return "properties";
  if (path.endsWith(".env") || path.startsWith(".env")) return "dotenv";
  if (path.endsWith(".toml")) return "toml";
  if (path.endsWith(".ini")) return "ini";
  return "typescript";
}

function fileWithContent(content: string, path = "src/config.ts"): FileInfo {
  return makeFile({
    path,
    languageId: langFromPath(path),
    content,
    lineCount: content.split("\n").length,
    charCount: content.length,
  });
}

describe("scanSecrets", () => {
  // ─── No-op cases ──────────────────────────────────────────────

  it("returns empty when no active file", () => {
    const result = scanSecrets(makeSnapshot(), {});
    expect(result.secretFindings).toHaveLength(0);
  });

  it("returns empty when active file has no content", () => {
    const result = scanSecrets(
      makeSnapshot({ activeFile: makeFile({ content: undefined }) }),
      {}
    );
    expect(result.secretFindings).toHaveLength(0);
  });

  it("returns empty for test files", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const key = "AKIAIOSFODNN7EXAMPLE1";', "src/auth.test.ts"),
      }),
      {}
    );
    expect(result.secretFindings).toHaveLength(0);
  });

  it("returns empty for clean file", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const x = 1;\nconst y = "hello";\n'),
      }),
      {}
    );
    expect(result.secretFindings).toHaveLength(0);
  });

  // ─── Layer 1: Provider Prefixes ────────────────────────────────

  // Data-driven: every ported provider rule must match a valid example (guards
  // against regex typos) and attribute it to the right ruleId.
  describe("ported provider formats (Layer 1)", () => {
    const rules = (c: string) =>
      (scanSecrets(makeSnapshot({ activeFile: fileWithContent(c) }), {}).secretFindings ?? []).map(
        (f) => f.ruleId
      );
    const A = (n: number) => "A".repeat(n);
    const h = (n: number) => "0123456789abcdef".repeat(Math.ceil(n / 16)).slice(0, n);
    const cases: Array<[string, string]> = [
      ["github-fine-grained-pat", `t="github_pat_${A(82)}"`],
      ["openai-key", `k="sk-${A(20)}T3BlbkFJ${A(20)}"`],
      ["anthropic-key", `k="sk-ant-api03-${A(30)}"`],
      ["huggingface-token", `k="hf_${A(34)}"`],
      ["twilio-key", `k="SK${h(32)}"`],
      ["sendgrid-key", `k="SG.${A(22)}.${A(43)}"`],
      ["shopify-token", `k="shpat_${h(32)}"`],
      ["mailgun-key", `k="key-${h(32)}"`],
      ["mailchimp-key", `k="${h(32)}-us1"`],
      ["square-token", `k="sq0atp-${A(22)}"`],
      ["digitalocean-token", `k="dop_v1_${h(64)}"`],
      ["pypi-token", `k="pypi-AgEIcHlwaS${A(50)}"`],
      ["postman-key", `k="PMAK-${h(24)}-${h(34)}"`],
      ["linear-key", `k="lin_api_${A(40)}"`],
      ["notion-token", `k="ntn_${A(36)}"`],
      ["figma-token", `k="figd_${A(40)}"`],
      ["databricks-token", `k="dapi${h(32)}"`],
      ["discord-webhook", "https://discord.com/api/webhooks/123456789/AbCdEf-_1xyz"],
      ["telegram-bot-token", `k="123456789:AA${A(33)}"`],
      ["slack-webhook", `https://hooks.slack.com/services/T00000000/B00000000/${A(24)}`],
      ["newrelic-key", `k="NRAK-${A(27)}"`],
      ["grafana-sa-token", `k="glsa_${A(32)}_${h(8)}"`],
      ["grafana-cloud-token", `k="glc_${A(32)}"`],
      ["vault-token", `k="hvs.${A(24)}"`],
      ["atlassian-token", `k="ATATT3${A(100)}"`],
      ["doppler-token", `k="dp.pt.${A(40)}"`],
      ["sentry-token", `k="sntrys_${A(40)}"`],
      ["supabase-token", `k="sbp_${h(40)}"`],
      ["planetscale-token", `k="pscale_tkn_${A(32)}"`],
      ["dropbox-token", `k="sl.${A(130)}"`],
      ["age-secret-key", `k="AGE-SECRET-KEY-1${A(58)}"`],
      ["rubygems-key", `k="rubygems_${h(48)}"`],
      ["flyio-token", `k="fo1_${A(40)}"`],
      ["terraform-cloud-token", `k="${A(14)}.atlasv1.${A(60)}"`],
      ["clojars-token", `k="CLOJARS_${"a".repeat(60)}"`],
      ["plaid-token", `k="access-sandbox-11111111-2222-3333-4444-555555555555"`],
      ["prefect-key", `k="pnu_${A(36)}"`],
      ["brevo-key", `k="xkeysib-${h(64)}-${A(16)}"`],
      ["typeform-token", `k="tfp_${A(40)}"`],
      ["duffel-token", `k="duffel_test_${A(40)}"`],
      ["easypost-key", `k="EZAK${A(50)}"`],
    ];
    it.each(cases)("detects %s", (id, example) => {
      expect(rules(example)).toContain(id);
    });
    it("does not fire any provider rule on benign prose", () => {
      expect(rules('const greeting = "hello world this is fine";')).toHaveLength(0);
    });
  });

  it("detects AWS access key (AKIA)", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const key = "AKIAIOSFODNN7EXAMPLE1";'),
      }),
      {}
    );
    expect(result.secretFindings!.length).toBeGreaterThanOrEqual(1);
    const finding = result.secretFindings![0];
    expect(finding.ruleId).toBe("aws-access-key");
    expect(finding.layer).toBe(1);
    expect(finding.severity).toBe("error");
    expect(finding.lineNumber).toBe(1);
  });

  it("detects AWS session key (ASIA)", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('AccessKeyId: "ASIAIOSFODNN7EXAMPLE1"'),
      }),
      {}
    );
    const finding = result.secretFindings!.find((f) => f.ruleId === "aws-access-key");
    expect(finding).toBeDefined();
  });

  it("detects GitHub personal access token", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";'
        ),
      }),
      {}
    );
    expect(result.secretFindings![0].ruleId).toBe("github-token");
    expect(result.secretFindings![0].severity).toBe("error");
  });

  it("detects Stripe live key", () => {
    // Build key dynamically to avoid GitHub push protection blocking this test file
    const prefix = "sk" + "_" + "live" + "_";
    const key = prefix + "a".repeat(24);
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(`stripe_key = "${key}";`),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.ruleId === "stripe-key")).toBe(true);
  });

  it("detects a Stripe restricted (rk_) live key", () => {
    const key = "rk" + "_" + "live" + "_" + "a".repeat(24);
    const result = scanSecrets(makeSnapshot({ activeFile: fileWithContent(`k = "${key}";`) }), {});
    expect(result.secretFindings!.some((f) => f.ruleId === "stripe-key")).toBe(true);
  });

  it("does NOT flag a Stripe publishable (pk_) key — public by design", () => {
    const key = "pk" + "_" + "live" + "_" + "a".repeat(24);
    const result = scanSecrets(makeSnapshot({ activeFile: fileWithContent(`k = "${key}";`) }), {});
    expect(result.secretFindings!.some((f) => f.ruleId === "stripe-key")).toBe(false);
  });

  it("detects Google API key", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'const key = "AIzaSyA-abcdefghijklmnopqrstuvwxyz12345";'
        ),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.ruleId === "google-api-key")).toBe(true);
  });

  it("detects Slack token", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('token = "xoxb-123456789012-abcdefghij";'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.ruleId === "slack-token")).toBe(true);
  });

  it("detects OpenAI API key", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'const key = "sk-proj-abcdefghijklmnopqrstuvwxyz";'
        ),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.ruleId === "openai-key")).toBe(true);
  });

  it("detects GitLab token", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('token = "glpat-abcdefghijklmnopqrst";'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.ruleId === "gitlab-token")).toBe(true);
  });

  it("detects private key block", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.ruleId === "private-key-block")).toBe(true);
  });

  it("does NOT detect AWS key in comment line", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('// const key = "AKIAIOSFODNN7EXAMPLE1";'),
      }),
      {}
    );
    expect(result.secretFindings).toHaveLength(0);
  });

  it("does NOT detect AWS key in hash comment", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('# key = "AKIAIOSFODNN7EXAMPLE1"'),
      }),
      {}
    );
    expect(result.secretFindings).toHaveLength(0);
  });

  // ─── Layer 2: Keyword + Assignment ─────────────────────────────

  it("detects password = literal string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('db_password = "Summer2026!"'),
      }),
      {}
    );
    const finding = result.secretFindings!.find((f) => f.layer === 2);
    expect(finding).toBeDefined();
    expect(finding!.ruleId).toBe("keyword-secret");
    expect(finding!.label).toBe("Hardcoded secret");
  });

  it("detects pwd variant", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('ml_ref_pwd: "admin123"'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("detects api_key assignment", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('STRIPE_API_KEY = "sk_test_123456"'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("detects secret with colon assignment (YAML)", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('jwt_secret: "my-super-secret-key"', "config.yml"),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("does NOT trigger on empty password", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('password = ""'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  it("does NOT trigger on placeholder 'changeme'", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('password = "changeme"'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  it("does NOT trigger on placeholder 'TODO'", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('secret = "TODO"'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  it("does NOT trigger on env var reference", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('password = "process.env.DB_PASSWORD"'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  it("does NOT trigger on template variable", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('secret = "${SECRET_KEY}"'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  it("does NOT trigger on angle-bracket placeholder", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('password = "<your-password-here>"'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  // ─── Layer 2b: Unquoted values in YAML/config ──────────────────

  it("detects unquoted password in YAML", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("ml_ref_password: vale", "config.yml"),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("detects unquoted db_password in YAML", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("db_password: Summer2026!", "application.yml"),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("detects unquoted secret in .properties", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: makeFile({
          path: "application.properties",
          languageId: "properties",
          content: "spring.datasource.password=dbpass123",
          lineCount: 1,
          charCount: 36,
          isActive: true,
        }),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("detects unquoted token in .env file", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: makeFile({
          path: ".env",
          languageId: "dotenv",
          content: "AUTH_TOKEN=my-secret-token-value",
          lineCount: 1,
          charCount: 31,
          isActive: true,
        }),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("does NOT detect unquoted value in .ts file (would false positive on code)", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("const password = getPassword()"),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  // ─── Layer 2c: field-echo & URL query-string false positives (dogfood) ──

  // The unquoted value just echoes a credential field name — no secret.
  it("does NOT flag an unquoted value that echoes the field name (token: access_token)", () => {
    const result = scanSecrets(
      makeSnapshot({ activeFile: fileWithContent("token: access_token", "config.yml") }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  it("does NOT flag api_key: api_key / clientSecret: clientSecret echoes", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("api_key: api_key\nclientSecret: clientSecret", "config.yml"),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  // A secret keyword appearing as a URL query parameter is not an assignment; the
  // placeholder value must not be flagged, but the rest of the query string must
  // not be swept into the "value" either.
  it("does NOT flag a placeholder token in a URL query string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          "url: https://api.example.com/oauth?token=access_token&client_id=abc",
          "config.yml"
        ),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  it("does NOT flag a placeholder access_token in a quoted URL value", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'redirect: "https://host/callback?access_token=TOKEN&state=xyz"',
          "config.yml"
        ),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 2)).toHaveLength(0);
  });

  // Positive controls — the fix must not blind the scanner to real secrets.
  it("STILL flags a bare unquoted non-keyword value (ml_ref_password: vale)", () => {
    const result = scanSecrets(
      makeSnapshot({ activeFile: fileWithContent("ml_ref_password: vale", "config.yml") }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("STILL flags a real high-entropy secret in a URL query string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          "url: https://h/cb?api_key=Xk9Qm2Lp8Rv4Tn6Wz0Bc7Df&x=y",
          "config.yml"
        ),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2)).toBe(true);
  });

  it("STILL flags a password= credential in a URL query string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("u: https://h/cb?password=hunter2xy", "config.yml"),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 2 || f.layer === 4)).toBe(true);
  });

  // ─── Layer 3: Shannon Entropy ──────────────────────────────────

  it("detects high-entropy string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const config = "a8K3mZp9Qw2LxNvB7yH4jR6tF5gE1cD";'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 3)).toBe(true);
  });

  it("does NOT trigger on low-entropy string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const msg = "hello world this is a test message";'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT trigger on URL", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const url = "https://api.example.com/v2/users/auth";'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT trigger on file path", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const path = "/usr/local/bin/something-here";'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  // Noise benchmark (engine 0.1.26): the high-entropy rule fired on identifiers,
  // hostnames and translated text. These must NOT be high-entropy findings.
  describe("high-entropy noise guards", () => {
    const l3 = (c: string, p = "a.ts") =>
      (scanSecrets(makeSnapshot({ activeFile: fileWithContent(c, p) }), {}).secretFindings ?? [])
        .filter((f) => f.layer === 3)
        .length;
    it("skips AWS model / Smithy shape ids (contain #)", () => {
      expect(l3('const s = "com.amazonaws.kendra#ListDataSources";')).toBe(0);
      expect(l3('shapeId = "smithy.api#ClusterNotFoundException";')).toBe(0);
    });
    it("skips reverse-DNS ids and dotted hostnames", () => {
      expect(l3('pkg = "com.amazonaws.services.dynamodb.model";')).toBe(0);
      expect(l3('addr = "node1.dc2.internal.e5b0abc9f3d2.consul";', "a.go")).toBe(0);
    });
    it("skips non-ASCII translation text (.po / docs)", () => {
      expect(l3('msgstr "パスワードを入力"', "a.po")).toBe(0);
      expect(l3('desc = "账户密码配置选项"', "a.md")).toBe(0);
    });
    it("STILL flags a real high-entropy token (no dots/#/non-ascii)", () => {
      expect(l3('const c = "a8K3mZp9Qw2LxNvB7yH4jR6tF5gE1cD";')).toBeGreaterThan(0);
    });
  });

  // Dogfood: a long relative path scores high entropy and was flagged "Potential
  // secret". A filesystem path (absolute, relative ./ ../, home ~/, or bare a/b/c)
  // is word segments, not a credential.
  it("does NOT flag a relative path with high entropy (../a/b/c)", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          "build job: '../Mend_And_Fortify/Fortify/fortify-emrg-viewgen-scr-Svcs-Backend-v2'",
          "pipeline.yml"
        ),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT flag ./ , ~/ , or bare multi-segment paths", () => {
    for (const line of [
      "src: './src/Components/EmergencyViewGen/FortifyScanService/index.module.tsx'",
      "p: '~/projects/Mend_And_Fortify/Fortify/fortify-emrg-viewgen-scr'",
      "p: 'Mend_And_Fortify/Fortify/fortify-emrg-viewgen-scr-Svcs-Backend'",
    ]) {
      const result = scanSecrets(
        makeSnapshot({ activeFile: fileWithContent(line, "pipeline.yml") }),
        {}
      );
      expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
    }
  });

  // Positive controls — the path guard must not blind the entropy layer.
  it("STILL flags a base64-ish secret that has only a single slash", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("const c = 'aGVsbG8gd29ybGQK2n9Qz/xR4tF5gE1cDmZ';", "app.ts"),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 3)).toBe(true);
  });

  it("STILL flags a provider key embedded in a path-like value (Layer 1)", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent("k: 'config/AKIAIOSFODNN7EXAMPLE1/x'", "pipeline.yml"),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("does NOT trigger on short string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const x = "aB3$kM9";'), // 7 chars, below threshold
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT trigger on container image reference", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'image: "cr.l5d.io/linkerd/proxy:stable-2.14.0"',
          "deployment.yml"
        ),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT trigger on AWS ARN", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'role = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com"'
        ),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT trigger on ECR image URI", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'image: "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon-k8s-cni:v1.15.1"',
          "values.yml"
        ),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT trigger on version number string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('version = "1.23.456.789-beta"'),
      }),
      {}
    );
    expect(result.secretFindings!.filter((f) => f.layer === 3)).toHaveLength(0);
  });

  it("does NOT double-report line already caught by Layer 1", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('key = "AKIAIOSFODNN7EXAMPLE1";'),
      }),
      {}
    );
    // Should have exactly 1 finding (Layer 1), not 2
    const findings = result.secretFindings!.filter(
      (f) => f.lineNumber === 1
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].layer).toBe(1);
  });

  // ─── Layer 4: Connection Strings ───────────────────────────────

  it("detects MongoDB connection string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const uri = "mongodb://admin:pass123@host:27017/mydb";'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 4)).toBe(true);
  });

  it("detects PostgreSQL connection string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('db_url = "postgresql://user:s3cret@db.acme.io:5432/app";'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 4)).toBe(true);
  });

  it("detects JDBC connection string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          'url = "jdbc:mysql://host:3306/db?user=root&password=pass";'
        ),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 4)).toBe(true);
  });

  it("detects .NET connection string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          '"ConnectionString": "Server=myhost;Database=mydb;User=sa;Password=secret123"'
        ),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 4)).toBe(true);
  });

  it("does NOT flag a connection URL with no embedded credentials", () => {
    // Spring's spring.datasource.url — host:port/db only, password is elsewhere
    const props = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent(
          "spring.datasource.url=jdbc:postgresql://plt-db-host:5432/platform\n",
          "application.properties"
        ),
      }),
      {}
    ).secretFindings!;
    expect(props.some((f) => f.ruleId.startsWith("connection-string"))).toBe(false);

    expect(
      scanSecrets(
        makeSnapshot({ activeFile: fileWithContent('const u = "mongodb://localhost:27017/app";') }),
        {}
      ).secretFindings!.some((f) => f.layer === 4)
    ).toBe(false);
  });

  it("detects Redis connection string", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('redis_url = "redis://user:pass@redis-host:6379/0";'),
      }),
      {}
    );
    expect(result.secretFindings!.some((f) => f.layer === 4)).toBe(true);
  });

  // ─── Integration ──────────────────────────────────────────────

  it("generates secret-in-content waste pattern when secrets found", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('password = "hunter2"'),
      }),
      {}
    );
    expect(result.wastePatterns!.some((w) => w.ruleId === "secret-in-content")).toBe(true);
  });

  it("does NOT generate waste pattern when no secrets found", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('const x = 1;'),
      }),
      {}
    );
    expect(result.wastePatterns ?? []).toHaveLength(0);
  });

  it("reports secret-packed files past the old caps (cap is now 1000)", () => {
    // Keyword must be immediately followed by `=`, so use a real keyword name
    // (api_key) with distinct high-entropy values — one finding per line.
    const lines = Array.from(
      { length: 70 },
      (_, i) => `api_key = "sk-live-${i}-Xk9Qm2Lp8Rv4Tn6Wz0Bc"`
    ).join("\n");
    const result = scanSecrets(
      makeSnapshot({ activeFile: fileWithContent(lines) }),
      {}
    );
    // all 70 reported — not silently truncated at the old 10 or 50 cap
    expect(result.secretFindings!.length).toBe(70);
  });

  // Dogfood (CredData): a ~150 KB file with a real secret used to be skipped
  // entirely by the old 100 KB cap and reported as clean. It must be scanned now.
  it("scans files between 100 KB and 1 MB (old limit silently hid these)", () => {
    const filler = "// a harmless comment line of code\n".repeat(4000); // ~140 KB
    const content = filler + 'aws_key = "AKIAIOSFODNN7EXAMPLE1"\n';
    expect(content.length).toBeGreaterThan(100_000);
    expect(content.length).toBeLessThan(1_000_000);
    const result = scanSecrets(makeSnapshot({ activeFile: fileWithContent(content) }), {});
    expect(result.secretFindings!.some((f) => f.ruleId === "aws-access-key")).toBe(true);
  });

  it("still skips files over 1 MB (bounded work)", () => {
    const content = "x".repeat(1_000_001) + '\naws_key = "AKIAIOSFODNN7EXAMPLE1"';
    const result = scanSecrets(makeSnapshot({ activeFile: fileWithContent(content) }), {});
    expect(result.secretFindings ?? []).toHaveLength(0);
  });

  it("redacts matched values in preview", () => {
    const result = scanSecrets(
      makeSnapshot({
        activeFile: fileWithContent('key = "AKIAIOSFODNN7EXAMPLE1"'),
      }),
      {}
    );
    const preview = result.secretFindings![0].matchPreview;
    expect(preview).toContain("****");
    expect(preview).not.toContain("AKIAIOSFODNN7EXAMPLE1");
  });
});

// ─── Adversarial hardening (v0.7.0) ─────────────────────────────
// Regression guards for findings from the cross-engine adversarial corpus:
// two entropy-layer false positives + two coverage gaps.
describe("scanSecrets — adversarial hardening", () => {
  const scan = (content: string, path = "src/config.ts") =>
    scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {});

  // False positives that the entropy layer used to flag.
  it("does NOT flag Subresource-Integrity / checksum digests", () => {
    const r = scan('integrity: "sha256-a8K3mZp9Qw2LxNvB7yH4jR6tF5gE1cD0uP2qXrJ8vK="');
    expect(r.secretFindings).toHaveLength(0);
  });

  it("does NOT flag sha512 integrity digests", () => {
    const r = scan('"integrity": "sha512-9xK3mZp7Qw2LxNvB4yH8jR6tF5gE1cD0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345=="');
    expect(r.secretFindings).toHaveLength(0);
  });

  it("does NOT flag base64 data URIs", () => {
    const r = scan('const img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ";');
    expect(r.secretFindings).toHaveLength(0);
  });

  // Coverage gaps that used to be missed.
  it("flags npm authentication tokens", () => {
    const r = scan(
      "//registry.npmjs.org/:_authToken=npm_9xK3mZp7Qw2LxNvB4yH8jR6tF5gE1cD0aBcD",
      ".npmrc"
    );
    expect(r.secretFindings.some((f) => f.ruleId === "npm-token")).toBe(true);
  });

  it("flags credentials embedded in a URL", () => {
    const r = scan('const u = "https://admin:Sup3rS3cr3tPw@internal.acme-corp.com/api";');
    expect(r.secretFindings.some((f) => f.ruleId === "url-embedded-credentials")).toBe(true);
  });

  it("flags credentials in non-http URL schemes too", () => {
    const r = scan('const r = "redis://user:pass99word@redis-host:6379/0";');
    expect(r.secretFindings.length).toBeGreaterThan(0);
  });

  // Markdown heading-line gap: "#" is a heading in Markdown, not a comment, so a
  // secret sitting on a heading line must still be scanned.
  it("flags a secret on a Markdown heading line", () => {
    const r = scan("# ghp_R8xQ2vN7wZ4kLpM1aB3cD5eF6gH9jK0mN2pQ", "README.md");
    expect(r.secretFindings.some((f) => f.ruleId === "github-token")).toBe(true);
  });

  it("flags a secret in Markdown prose", () => {
    const r = scan("Set your token: ghp_R8xQ2vN7wZ4kLpM1aB3cD5eF6gH9jK0mN2pQ", "docs/setup.md");
    expect(r.secretFindings.some((f) => f.ruleId === "github-token")).toBe(true);
  });

  it("still skips real HTML comments in Markdown", () => {
    const r = scan("<!-- old token was ghp_R8xQ2vN7wZ4kLpM1aB3cD5eF6gH9jK0mN2pQ -->", "README.md");
    expect(r.secretFindings).toHaveLength(0);
  });

  it("still treats leading # as a comment in code files", () => {
    // Regression: the Markdown change must not re-enable scanning of "#" comments
    // in ordinary source files.
    const r = scan('# const key = "ghp_R8xQ2vN7wZ4kLpM1aB3cD5eF6gH9jK0mN2pQ"', "src/app.py");
    expect(r.secretFindings).toHaveLength(0);
  });

  // Entropy-layer false positive: RDF/Turtle prefix declarations are high-entropy
  // structured text (URIs + punctuation + spaces), not secrets.
  it("does NOT flag RDF/Turtle @prefix declarations", () => {
    const rdf = [
      'rdf_content.append("@prefix : <http://example.org/> .")',
      'rdf_content.append("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .")',
      'rdf_content.append("@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .")',
    ].join("\n");
    const r = scan(rdf, "advanced_knowledge_graph.py");
    expect(r.secretFindings).toHaveLength(0);
  });

  it("does NOT flag high-entropy strings that contain spaces (prose/markup)", () => {
    const r = scan('const q = "SELECT ?s ?p ?o WHERE { ?s ?p ?o } LIMIT 100";');
    expect(r.secretFindings).toHaveLength(0);
  });

  it("still flags a genuine contiguous high-entropy token", () => {
    // Guard against over-correction: a real token (no spaces, no URI) still fires.
    // Neutral variable name so the entropy layer — not the keyword layer — is exercised.
    const r = scan('const blob = "a8K3mZp9Qw2LxNvB7yH4jR6tF5gE1cD0uP2qX";');
    expect(r.secretFindings.some((f) => f.ruleId === "high-entropy")).toBe(true);
  });
});

// ─── Credential lifetime classification ────────────────────────
describe("scanSecrets — credential lifetime", () => {
  const scan = (content: string, path = "src/config.ts") =>
    scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {});
  const first = (content: string, path = "src/config.ts") => scan(content, path).secretFindings![0];

  it("marks a static AWS access key (AKIA) as long-lived", () => {
    const f = first('const key = "AKIAIOSFODNN7EXAMPLE1";');
    expect(f.lifetime).toBe("long-lived");
    expect(f.suggestion).toMatch(/short-lived/i);
  });

  it("marks an AWS STS session key (ASIA) as short-lived", () => {
    const f = first('AccessKeyId: "ASIAIOSFODNN7EXAMPLE1"');
    expect(f.ruleId).toBe("aws-access-key");
    expect(f.lifetime).toBe("short-lived");
    expect(f.suggestion).not.toMatch(/short-lived/i);
  });

  it("marks a private key block as long-lived", () => {
    const f = first("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----");
    expect(f.lifetime).toBe("long-lived");
  });

  it("marks a GitHub token as long-lived", () => {
    const f = first('const t = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";');
    expect(f.lifetime).toBe("long-lived");
  });

  it("marks a connection string as long-lived", () => {
    const f = first('const uri = "mongodb://admin:pass123@host:27017/db";');
    expect(f.lifetime).toBe("long-lived");
  });

  it("marks a JWT with an exp claim as short-lived", () => {
    // {"alg":"HS256","typ":"JWT"} . {"sub":"1","exp":9999999999} . sig
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const f = first(`const t = "${jwt}";`);
    expect(f.lifetime).toBe("short-lived");
  });

  it("leaves generic high-entropy findings as unknown lifetime", () => {
    const f = first('const blob = "a8K3mZp9Qw2LxNvB7yH4jR6tF5gE1cD0uP2qX";');
    expect(f.ruleId).toBe("high-entropy");
    expect(f.lifetime).toBe("unknown");
  });

  it("classifies a detected JWT WITHOUT an exp claim as unknown (not short-lived)", () => {
    // A JWT is now detected explicitly (Layer 1 `jwt`). Its payload
    // {"sub":"user123","role":"admin","iat":…} has NO exp — so lifetime must be
    // unknown, not short-lived.
    const jwtNoExp =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwfQ.K7pQ2mZx9RtVn4LbW8yE3jF6gD1cA5sN0uP2qXrJ8v";
    const f = first(`const t = "${jwtNoExp}";`);
    expect(f.ruleId).toBe("jwt");
    expect(f.lifetime).toBe("unknown");
  });
});

// ─── Shannon Entropy Unit Tests ────────────────────────────────

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single repeated character", () => {
    expect(shannonEntropy("aaaaaaa")).toBe(0);
  });

  it("returns 1.0 for two alternating characters", () => {
    expect(shannonEntropy("abababab")).toBeCloseTo(1.0, 1);
  });

  it("returns higher entropy for random-looking string", () => {
    const entropy = shannonEntropy("aB3$kM9!xZ2@pL7");
    expect(entropy).toBeGreaterThan(3.5);
  });

  it("returns lower entropy for dictionary word", () => {
    const entropy = shannonEntropy("password");
    expect(entropy).toBeLessThan(3.0);
  });

  it("returns high entropy for base64-like string", () => {
    const entropy = shannonEntropy("dGhpcyBpcyBhIHRlc3Qgc3RyaW5n");
    expect(entropy).toBeGreaterThan(3.5);
  });
});

// Regressions from dogfooding vet on a real repo: 21/21 warnings were false
// positives — generated SVG/asset entropy, inline CSS/JS entropy, and a keyword
// match on a field *name* whose value wasn't a literal secret.
describe("scanSecrets — false-positive guards", () => {
  const scan = (content: string, path = "src/app.ts") =>
    scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
    [];

  describe("entropy — generated/asset files and markup", () => {
    it("skips the entropy layer for SVG files", () => {
      const svg = `<svg><path d="M10,20C30,40,${"ABCdef123GHIjkl456MNOpqr".repeat(4)}"/></svg>`;
      expect(scan(svg, "docs/diagram.svg")).toHaveLength(0);
    });

    it("skips minified bundles and source maps", () => {
      const blob = `x="${"aB3xY7zQ9wE2rT5uI8".repeat(6)}"`;
      expect(scan(blob, "dist/app.min.js")).toHaveLength(0);
      expect(scan(blob, "dist/app.js.map")).toHaveLength(0);
    });

    it("does not flag inline CSS/path data (structural punctuation) in source files", () => {
      const html = `<div style="fill:#a1b2c3;stroke:#d4e5f6;transform:matrix(1,0,0,1,${"X9y8Z7w6".repeat(4)})"></div>`;
      expect(scan(html, "public/index.html")).toHaveLength(0);
    });

    it("STILL flags a genuine high-entropy token in a normal file", () => {
      const f = scan(`const t = "aB3xY7zQ9wE2rT5uI8oP1kJ4nM6";`, "src/app.ts");
      expect(f.length).toBeGreaterThan(0);
      expect(f[0].ruleId).toBe("high-entropy");
    });

    it("does not entropy-flag a variable-rooted path (IDE macro)", () => {
      // $PROJECT_DIR$/… in a non-skipped file is still recognized as a path
      expect(scan('afterPath="$PROJECT_DIR$/emrg-webapp/.project"', "notes.txt")).toHaveLength(0);
      expect(scan('p = "%APPDATA%\\\\app\\\\config"', "notes.txt")).toHaveLength(0);
    });

    it("skips the entropy layer for IDE/build metadata and markup files", () => {
      const path = 'x="$PROJECT_DIR$/emrg-webapp/very-long-ish-value-aB3xY7"';
      expect(scan(path, ".idea/workspace.xml")).toHaveLength(0);
      expect(scan('<classpathentry path="src/main/aB3xY7zQ9wE2rT5uI8"/>', "x/.classpath")).toHaveLength(0);
      expect(scan('<div class="aB3xY7zQ9wE2rT5uI8oP1kJ4nM6 flex">', "app.component.html")).toHaveLength(0);
    });

    it("STILL catches a real provider key inside an entropy-skipped file", () => {
      // only the entropy heuristic is skipped — provider/keyword layers still run
      const f = scan('<script>const k = "AKIAIOSFODNN7EXAMPLE1";</script>', "index.html");
      expect(f.some((x) => x.ruleId === "aws-access-key")).toBe(true);
    });
  });

  describe("keyword — value must be a credential literal, not a field echo", () => {
    it("does not flag a *_key field whose value is a bare word/identifier", () => {
      expect(scan(`const body = JSON.stringify({ anthropic_api_key: "key" });`)).toHaveLength(0);
      expect(scan(`const h = { api_key: "apiKey" };`)).toHaveLength(0);
      expect(scan(`password: "password"`)).toHaveLength(0);
    });

    it("does not flag a kebab/snake field-echo value (access-token, refresh_token)", () => {
      expect(scan(`String ACCESS_TOKEN = "access-token";`)).toHaveLength(0);
      expect(scan(`const refreshToken = "refresh_token";`)).toHaveLength(0);
      expect(scan(`secret = "my-secret-key"`)).toHaveLength(0);
    });

    it("does not flag C/C++ parser-token assignments (code expressions)", () => {
      // misclassified source (unmapped ext → plaintext → treated as config)
      const scanC = (c: string) =>
        scanSecrets(makeSnapshot({ activeFile: fileWithContent(c, "parser.cpp") }), {})
          .secretFindings ?? [];
      expect(scanC("cur_token = yyextra->lookahead_token;\n")).toHaveLength(0);
      expect(scanC("     SECRET = 641,\n")).toHaveLength(0);
      expect(scanC("token = new_token;\n")).toHaveLength(0);
      expect(scanC("auto &token = tokens[i];\n")).toHaveLength(0);
      expect(scanC("int max_token = -1;\n")).toHaveLength(0);
      // positive control: a real quoted secret in the same file still flags
      expect(scanC('const char *api_token = "aB3xY7zQ9wE2rT5uI8";\n').length).toBeGreaterThan(0);
    });

    it("does not flag a boolean/integer config flag on a secret-named field", () => {
      const scanY = (c: string) =>
        scanSecrets(makeSnapshot({ activeFile: fileWithContent(c, "kong.yaml") }), {})
          .secretFindings ?? [];
      expect(scanY("kong_revoke_access_token: true\n")).toHaveLength(0);
      expect(scanY("enable_secret: false\n")).toHaveLength(0);
      expect(scanY("token_ttl: 3600\n")).toHaveLength(0);
      // positive control — a real value on the same field still flags
      expect(scanY('access_token: "aB3xY7zQ9wE2rT5"\n').length).toBeGreaterThan(0);
    });

    it("does not flag an AWS ARN that references a secret (not the secret itself)", () => {
      const yaml = scanSecrets(
        makeSnapshot({
          activeFile: fileWithContent(
            '      Resource: "arn:aws:secretsmanager:*:*:secret:plt/emrg/*"\n',
            "Role.yaml"
          ),
        }),
        {}
      ).secretFindings ?? [];
      expect(yaml).toHaveLength(0);
    });

    it("STILL flags a long multi-word value and an entropy-bearing token", () => {
      // 4-segment passphrase exceeds the 3-segment field-echo guard
      expect(scan(`const password = "correct-horse-battery-staple";`).length).toBeGreaterThan(0);
      // digits => real-token shape, not a field echo
      expect(scan(`String ACCESS_TOKEN = "ght-9f2Ka83Lx";`).length).toBeGreaterThan(0);
    });

    it("does not flag a *_key assigned a URL or path", () => {
      expect(scan(`const api_key = "https://api.example.com/v1";`)).toHaveLength(0);
      expect(scan(`secret = "/etc/ssl/private"`)).toHaveLength(0);
    });

    it("STILL flags a real hardcoded secret value", () => {
      const f = scan(`const api_key = "aB3xY7zQ9wE2rT5uI8oP1";`);
      expect(f.length).toBeGreaterThan(0);
      expect(f[0].ruleId).toBe("keyword-secret");
    });
  });

  // Dogfood regressions: a real codebase produced these 0-real findings.
  describe("placeholder / non-secret values from real-world dogfooding", () => {
    it("does not flag {{...}} template placeholders", () => {
      expect(scan("const token = `{{${name}}}`;")).toHaveLength(0);
      expect(scan(`const h = { bearerToken: '{{bearerToken}}' };`)).toHaveLength(0);
      expect(scan(`const p = { password: "{{password}}" };`)).toHaveLength(0);
    });

    it("does not flag obvious example literals (…-here / …-goes-here)", () => {
      expect(scan(`const bearerToken = "oauth2-token-here";`)).toHaveLength(0);
      expect(scan(`const api_key = "api-key-goes-here";`)).toHaveLength(0);
    });

    it("does not flag GitHub Actions id-token: write permission (YAML)", () => {
      const f =
        scanSecrets(
          makeSnapshot({
            activeFile: fileWithContent("permissions:\n  id-token: write\n", ".github/workflows/ci.yml"),
          }),
          {}
        ).secretFindings ?? [];
      expect(f).toHaveLength(0);
    });

    it("does not flag the word 'secret:' inside a help/echo string (prose)", () => {
      const f =
        scanSecrets(
          makeSnapshot({
            activeFile: fileWithContent(
              'echo "2. Add as repository secret:"\n',
              ".github/workflows/feature.yml"
            ),
          }),
          {}
        ).secretFindings ?? [];
      expect(f).toHaveLength(0);
    });

    it("does not flag a URL whose password is a variable (GitHub Actions idiom)", () => {
      const f =
        scanSecrets(
          makeSnapshot({
            activeFile: fileWithContent(
              'git clone https://x-access-token:${GH_TOKEN}@github.com/org/repo.git\n',
              ".github/workflows/feature.yml"
            ),
          }),
          {}
        ).secretFindings ?? [];
      expect(f).toHaveLength(0);
    });

    it("STILL flags a URL with a literal embedded password", () => {
      const f =
        scanSecrets(
          makeSnapshot({
            activeFile: fileWithContent(
              'const u = "https://admin:hunter2pass@db.acme-corp.com/x";',
              "src/db.ts"
            ),
          }),
          {}
        ).secretFindings ?? [];
      expect(f.some((x) => x.ruleId === "url-embedded-credentials")).toBe(true);
    });
  });

  // ─── Tier 2 precision guards (Samsung CredData false alarms) ──────
  describe("CredData false-alarm guards", () => {
    const scanC = (content: string, path = "src/app.cs") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    it("does NOT flag a .NET PublicKeyToken (public identity, not a secret)", () => {
      expect(scanC('ref assembly, PublicKeyToken="b77a5c561934e089"')).toHaveLength(0);
    });

    it("does NOT flag a screaming-snake env-var NAME used as a value", () => {
      expect(scanC('var secretEnv = "GCM_AZREPOS_SP_SECRET";')).toHaveLength(0);
    });

    it("does NOT flag credentials pointed at an RFC 2606 reserved/doc host", () => {
      expect(scanC('p = "http://john.doe:letmein123@proxy.example.com"')).toHaveLength(0);
      expect(scanC('p = "http://u:pw12345@api.example.org/x"')).toHaveLength(0);
    });

    it("DOES flag credentials at localhost / real services (CredData labels these real)", () => {
      expect(
        scanC('db = "postgres://user3:Pz9xk2qr@localhost:5555/app"').some((f) => f.layer === 4)
      ).toBe(true);
      expect(
        scanC('s = "https://pub9x:s3cretkey88@o1.ingest.sentry.io/42"').some(
          (f) => f.ruleId === "url-embedded-credentials"
        )
      ).toBe(true);
    });

    it("does NOT flag a sequential character run as high entropy", () => {
      expect(scanC('const s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";')).toHaveLength(0);
      expect(scanC('const n = "012345678901234567890";')).toHaveLength(0);
    });

    // Positive controls — the guards must not blind real secrets.
    it("STILL flags embedded creds at a real host", () => {
      expect(
        scanC('u = "postgres://admin:Pr0dP8ssxyz@db.acme-corp.io:5432/app"').some(
          (f) => f.layer === 4
        )
      ).toBe(true);
    });
    it("STILL flags a real high-entropy secret (not sequential)", () => {
      expect(
        scanC('const c = "a8K3mZp9Qw2LxNvB7yH4jR6tF";').some((f) => f.ruleId === "high-entropy")
      ).toBe(true);
    });
    it("STILL flags a real token value that is not an env-var name", () => {
      expect(
        scanC('api_key = "sk-live-Xk9Qm2Lp8Rv4Tn6Wz0Bc";').some((f) => f.ruleId === "keyword-secret")
      ).toBe(true);
    });
  });

  // ─── Tier 3 recall additions (CredData detection gaps) ───────────
  describe("CredData detection gaps", () => {
    const scanC = (content: string, path = "src/app.cs") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    // JWTs — detected explicitly, including unquoted `Bearer eyJ…` the entropy
    // layer never saw.
    it("detects a JWT (eyJ.eyJ.sig), quoted or in an Authorization header", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV";
      expect(scanC(`const t = "${jwt}";`).some((f) => f.ruleId === "jwt")).toBe(true);
      expect(scanC(`Authorization: Bearer ${jwt}`).some((f) => f.ruleId === "jwt")).toBe(true);
    });

    // Generic key fields (the biggest gap: 9% → up). The value drives it, but the
    // field name `app_key`/`key`/`appKey` is now recognized even below the entropy
    // threshold.
    it("flags generic key fields missed before (app_key / key / appKey / MY_KEY)", () => {
      expect(scanC('app_key = "a3f9c2e81b7d4056af12cd34ef567890";').length).toBeGreaterThan(0);
      expect(scanC('key = "a3f9c2e81b7d4056af12cd34";').length).toBeGreaterThan(0);
      expect(scanC('appKey = "a3f9c2e81b7d4056af12cd34";').length).toBeGreaterThan(0);
      expect(scanC("MY_KEY=a3f9c2e81b7d4056af12cd34", "app.env").length).toBeGreaterThan(0);
    });

    // Negative controls for the bare `key` keyword — must NOT turn English words
    // or public keys into secrets.
    it("does NOT flag English -key words or public keys", () => {
      for (const kw of ["monkey", "donkey", "turnkey", "hockey"]) {
        expect(scanC(`${kw} = "a3f9c2e81b7d4056af12cd34";`)).toHaveLength(0);
      }
      expect(scanC('public_key = "a3f9c2e81b7d4056af12cd34";')).toHaveLength(0);
      expect(scanC('pubkey = "a3f9c2e81b7d4056af12cd34";')).toHaveLength(0);
      expect(scanC('publicKey = "a3f9c2e81b7d4056af12cd34";')).toHaveLength(0);
    });

    it("does NOT flag a dotted i18n/property path as a key value", () => {
      expect(scanC('const key = "home.title";')).toHaveLength(0);
      expect(scanC('app_key = "app.module.name";')).toHaveLength(0);
      // but a dotted value carrying digits/entropy is still a secret
      expect(scanC('key = "a1b2.c3d4e5f6a7b8c9";').length).toBeGreaterThan(0);
    });
  });

  // ─── Tier 2b: keyword-rule precision (CredData v0.1.10 false alarms) ──
  describe("keyword-rule precision guards", () => {
    const scanC = (content: string, path = "src/app.cs") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    it("skips short key values (<8 chars) but keeps short passwords", () => {
      expect(scanC('correlationKey = ".xsrf"')).toHaveLength(0); // short, non-password
      expect(scanC('db_password = "Sum24!"').length).toBeGreaterThan(0); // password stays
    });

    it("skips sentence / whitespace values", () => {
      expect(scanC('key = "Failed to retrieve the generated key."')).toHaveLength(0);
      expect(scanC('secret = "Test Secret"')).toHaveLength(0);
    });

    it("skips test/mock/expected fixture fields", () => {
      expect(scanC('MOCK_ACCESS_TOKEN = "at0987654321xyz"')).toHaveLength(0);
      expect(scanC('expectedPassword = "letmein123"')).toHaveLength(0);
      // but a real field with 'test' only as a substring is NOT skipped
      expect(scanC('latest_token = "a3f9c2e81b7d4056af12cd34"').length).toBeGreaterThan(0);
    });

    it("skips structural / code 'key' contexts", () => {
      expect(scanC('key="keyEquivalentModifierMask"')).toHaveLength(0); // camel identifier
      expect(scanC('key = "uint32"')).toHaveLength(0); // Go struct-tag type
      expect(scanC('MYSQL_ROOT_PASSWORD: root', "docker-compose.yml")).toHaveLength(0); // trivial
    });

    it("skips Windows / backslash paths in the entropy layer", () => {
      expect(scanC('const p = "C:\\\\build\\\\bin\\\\Release\\\\app.pdb";')).toHaveLength(0);
    });
  });

  // ─── Authorization header credentials (the ~800-secret gap no tool caught) ──
  describe("auth-header detection", () => {
    const scanC = (content: string, path = "src/app.cs") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];
    // dXNlcjpwYXNzd29yZA== === base64("user:password")

    it("flags Basic / Bearer / NTLM Authorization credentials", () => {
      expect(scanC("Authorization: Basic dXNlcjpwYXNzd29yZA==")[0]?.ruleId).toBe("auth-header-basic");
      expect(scanC("Authorization: Bearer a1b2c3d4e5f6g7h8i9j0")[0]?.ruleId).toBe(
        "auth-header-bearer"
      );
      expect(scanC("Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAA=")[0]?.ruleId).toBe(
        "auth-header-ntlm"
      );
      expect(scanC('Proxy-Authorization: "Basic dXNlcjpwYXNzd29yZA=="')[0]?.ruleId).toBe(
        "auth-header-basic"
      );
    });

    it("does NOT flag placeholder / variable tokens", () => {
      expect(scanC("Authorization: Bearer ${ACCESS_TOKEN}")).toHaveLength(0);
      expect(scanC("Authorization: Bearer <access_token>")).toHaveLength(0);
      expect(scanC("Authorization: Bearer YOUR_TOKEN_HERE")).toHaveLength(0);
      expect(scanC("Authorization: Bearer token")).toHaveLength(0); // too short / bare word
    });

    it("rejects Basic values that don't decode to user:pass", () => {
      expect(scanC("Authorization: Basic YWJjZGVmZ2hpams=")).toHaveLength(0);
    });

    it("attributes a Bearer JWT to the jwt rule, not a double finding", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV";
      const f = scanC(`Authorization: Bearer ${jwt}`);
      expect(f).toHaveLength(1);
      expect(f[0].ruleId).toBe("jwt");
    });

    it("flags a standalone `Basic <base64>` (JSON value, no Authorization: prefix)", () => {
      // ZHR4OnBhc3N3b3Jk === base64("dtx:password")
      expect(scanC('{ "value": "Basic ZHR4OnBhc3N3b3Jk" }', "a.json")[0]?.ruleId).toBe(
        "auth-header-basic"
      );
      // prose "Basic authentication" must NOT flag (doesn't decode to user:pass)
      expect(scanC("Basic authentication is required")).toHaveLength(0);
    });
  });

  // ─── JSON quoted-key detection + placeholder URL creds (v0.1.11 gaps) ──
  describe("JSON keyword detection + placeholder URL creds", () => {
    const scanC = (content: string, path = "config.json") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    it('detects quoted JSON keys ("token": "…", "password": "…")', () => {
      expect(scanC('{ "token": "550e8400-e29b-41d4-a716-446655440000" }').length).toBeGreaterThan(0);
      expect(scanC('{ "password": "Sup3rS3cr3tVal" }').length).toBeGreaterThan(0);
      expect(scanC('{ "api_key": "a3f9c2e81b7d4056af12cd34" }').length).toBeGreaterThan(0);
    });

    it("does NOT flag structural / non-secret JSON pairs", () => {
      expect(scanC('{ "name": "John Doe" }')).toHaveLength(0);
      expect(scanC('{ "type": "string" }')).toHaveLength(0);
      expect(scanC('{ "key": "id" }')).toHaveLength(0); // short value
    });

    it("does NOT flag placeholder passwords in URL credentials", () => {
      expect(scanC('u = "http://minio:changeme@storage:9000"', "a.yaml")).toHaveLength(0);
      expect(scanC('u = "http://user:password@host:8080"', "a.md")).toHaveLength(0);
      // but a real password at a real host still flags
      expect(
        scanC('u = "http://admin:Pr0dP8ssxyz@db.acme.io"', "a.cs").some(
          (f) => f.ruleId === "url-embedded-credentials"
        )
      ).toBe(true);
    });
  });

  // ─── Randomness slice: short all-letter values on non-password fields ──
  describe("short-word value guard (non-password keyword fields)", () => {
    const scanC = (content: string, path = "src/app.cs") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    it("skips short all-letter / reference values on key/token/secret fields", () => {
      expect(scanC('ClientSecret = "Whatever;"')).toHaveLength(0); // word + trailing punct
      expect(scanC("- key: Corefile", "a.yaml")).toHaveLength(0); // unquoted short word
      expect(scanC("api_key = process.env.API_KEY", "a.ts")).toHaveLength(0); // code reference
      expect(scanC("password = var.db_password", "a.tf")).toHaveLength(0); // terraform reference
    });

    it("STILL flags credential-shaped values (digits/entropy, ≥12-char passphrases)", () => {
      expect(scanC('app_key = "a3f9c2e81b7d4056af12cd34"').length).toBeGreaterThan(0);
      expect(scanC('token = "Ab3Xy9Qm2"').length).toBeGreaterThan(0); // short but has digits
      expect(scanC('jwt_secret: "my-super-secret-key"', "a.yaml").length).toBeGreaterThan(0); // ≥12
      expect(scanC('token = "550e8400-e29b-41d4-a716-446655440000"').length).toBeGreaterThan(0); // UUID
    });
  });

  // ─── JSON-driven false alarms + standalone Bearer (engine 0.1.21 follow-up) ──
  describe("JSON false-alarm cleanup + standalone Bearer", () => {
    const scanC = (content: string, path = "config.json") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    it("skips non-ASCII translation values", () => {
      expect(scanC('{ "lockPassword": "パスワード" }')).toHaveLength(0);
      expect(scanC('{ "password": "пароль" }')).toHaveLength(0);
      expect(scanC('{ "password": "账户密码" }')).toHaveLength(0);
    });

    it("skips version ranges and masked values", () => {
      expect(scanC('{ "getpass": "^0.1.1" }', "package.json")).toHaveLength(0);
      expect(scanC('{ "minipass": "~2.2.1" }', "package.json")).toHaveLength(0);
      expect(scanC('{ "password": "********************" }')).toHaveLength(0);
    });

    it("flags a standalone `Bearer <token>` (JSON value), rejects prose", () => {
      expect(scanC('{ "value": "Bearer ru4o7fYmZ9xKpQ2wErTy6uI" }')[0]?.ruleId).toBe(
        "auth-header-bearer"
      );
      expect(scanC("Bearer bonds are financial instruments")).toHaveLength(0);
    });
  });

  // ─── Structural keyword false alarms (engine 0.1.22 benchmark) ──
  describe("structural-value guards", () => {
    const scanC = (content: string, path = "src/app.go") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    it("skips Go struct tags, format strings, label keys, k8s keys, hex vectors", () => {
      expect(scanC('Field string `key:"value9,range=[1:5]"`')).toHaveLength(0);
      expect(scanC('key = "plugin.%s.src.subdir"')).toHaveLength(0);
      expect(scanC("TopologyKey: \"k8s.io/zone\"", "a.yaml")).toHaveLength(0);
      expect(scanC('token = "***REDACTED***"')).toHaveLength(0);
      expect(scanC("password = 'Passwort:'", "a.js")).toHaveLength(0);
      expect(scanC('Key = "0123456789abcdef0123"')).toHaveLength(0); // sequential hex
    });

    it("keeps passwords that contain code punctuation (non-password-only guard)", () => {
      expect(scanC('db_password = "P@ss,w0rd!"').length).toBeGreaterThan(0);
      expect(scanC('password = "a[b]c9d!Xy"').length).toBeGreaterThan(0);
    });

    it("keeps real keys / base64 (no code punctuation)", () => {
      expect(scanC('app_key = "a3f9c2e81b7d4056af12cd34"').length).toBeGreaterThan(0);
      expect(scanC('secret = "aGVsbG8vd29ybGQK2n9Qz="').length).toBeGreaterThan(0);
    });
  });

  // ─── Randomness gate + format-string nuance + UUID context (engine 0.1.23) ──
  describe("randomness gate, format-string nuance, UUID context", () => {
    const scanC = (content: string, path = "src/app.cs") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    // Item 1: a format specifier inside a RANDOM value is a password, not a template.
    it("keeps random passwords that happen to contain %s or [", () => {
      expect(scanC('password = "e!@$%s^&*j)_x+m."').length).toBeGreaterThan(0);
      expect(scanC('password = "[Y@969zXq!"').length).toBeGreaterThan(0);
      expect(scanC('key = "plugin.%s.src.subdir"')).toHaveLength(0); // real format string
    });

    // Item 2: non-password values must look random; passwords are exempt.
    it("drops non-random values on key/token/secret fields, keeps random ones", () => {
      expect(scanC('api_key = "server-2"')).toHaveLength(0);
      expect(scanC('secret = "Whatever"')).toHaveLength(0);
      expect(scanC('api_key = "aZ9$kq2!Lm8@"').length).toBeGreaterThan(0);
      expect(scanC('jwt_secret: "my-super-secret-key"', "a.yaml").length).toBeGreaterThan(0);
    });

    // Item 3: a UUID near a token/secret keyword is a credential (Go :=, func arg).
    it("flags UUID values near a token/secret keyword, not bare UUIDs", () => {
      expect(scanC('tokenC := "7154a8e2-1234-41d4-a716-446655440000"', "a.go").length).toBeGreaterThan(0);
      expect(scanC('setAuthToken("7154a8e2-1234-41d4-a716-446655440000")', "a.ts").length).toBeGreaterThan(0);
      expect(scanC('sessionId = "7154a8e2-1234-41d4-a716-446655440000"')).toHaveLength(0);
    });

    it("always flags an AKIA access key ID, even inside a URL", () => {
      expect(
        scanC(
          'url = "https://s3.amazonaws.com/b?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F2024"'
        ).some((f) => f.ruleId === "aws-access-key")
      ).toBe(true);
    });
  });

  // ─── Short passwords + new provider rules (engine 0.1.24 benchmark) ──
  describe("short passwords, PASETO/NKEY/salt/oauth", () => {
    const scanC = (content: string, path = "src/app.cs") =>
      scanSecrets(makeSnapshot({ activeFile: fileWithContent(content, path) }), {}).secretFindings ??
      [];

    it("flags short real passwords (≥4 chars), still skips junk and 1-3 char values", () => {
      expect(scanC('{ "password": "brcsn" }', "a.json").length).toBeGreaterThan(0);
      expect(scanC('pass = "ywriv"').length).toBeGreaterThan(0);
      expect(scanC('password = "ab12"').length).toBeGreaterThan(0);
      expect(scanC('{ "password": "root" }', "a.json")).toHaveLength(0); // junk
      expect(scanC('password = "test"')).toHaveLength(0); // junk
      expect(scanC('password = "ab"')).toHaveLength(0); // <4
      expect(scanC('password = "https://x.com/cb"')).toHaveLength(0); // URL, not a password
    });

    it("still skips bare-word echoes on non-password fields (token: access_token)", () => {
      expect(scanC("token: access_token", "a.yaml")).toHaveLength(0);
    });

    it("detects PASETO tokens and NATS NKEY seeds (gitleaks catches 0%)", () => {
      expect(scanC('const t = "v2.local.AAAAAAAAAAbbbbbbbbbb"')[0]?.ruleId).toBe("paseto");
      expect(
        scanC('seed = "SUAEXAMPLE234567ABCDEFGH234567ABCDEFGH234567ABCDEFGH23"')[0]?.ruleId
      ).toBe("nkey-seed");
    });

    it("detects salt and oauth_signature values", () => {
      expect(scanC('salt = "2e1f3a9c8b7d6e5f0a1b2c3d"').length).toBeGreaterThan(0);
      expect(scanC('oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D"').length).toBeGreaterThan(0);
    });
  });
});
