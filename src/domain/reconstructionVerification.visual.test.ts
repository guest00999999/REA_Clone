import { crc32, deflateSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import { classifyBrowserCompleteness } from "./browserCompleteness.js";
import { createEvidence, type Evidence } from "./evidence.js";
import { createEvidenceBundle } from "./evidenceBundle.js";
import { jsonValueSchema, type JsonValue } from "./jsonValue.js";
import { verifyReconstruction } from "./reconstructionVerification.js";
import { reconstructionSpecificationSchema } from "./reconstructionVerificationSchemas.js";
import { createResidualUnknown } from "./residualUnknown.js";
import {
  createWebScreenshotArtifact,
  type WebScreenshotArtifact,
} from "./webScreenshot.js";
import { comparePngScreenshots } from "./webScreenshotPixels.js";

const CDP_PROVIDER = {
  id: "rea-cdp-browser",
  name: "REA Chrome DevTools Protocol observation provider",
  version: "2",
};

const SIZE = 4;
const WHITE = [255, 255, 255, 255] as const;
const BLACK = [0, 0, 0, 255] as const;

/** White RGBA PNG; `changed` pixels (row-major indexes) are painted black. */
const png = (
  changed: readonly number[] = [],
  width = SIZE,
  height = SIZE,
): Buffer => {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  const rows: number[] = [];
  for (let row = 0; row < height; row += 1) {
    rows.push(0);
    for (let column = 0; column < width; column += 1)
      rows.push(...(changed.includes(row * width + column) ? BLACK : WHITE));
  }
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(Buffer.from(rows))),
    chunk("IEND", Buffer.alloc(0)),
  ]);
};

const chunk = (type: string, data: Buffer): Buffer => {
  const result = Buffer.alloc(12 + data.byteLength);
  result.writeUInt32BE(data.byteLength, 0);
  result.write(type, 4, 4, "ascii");
  data.copy(result, 8);
  result.writeUInt32BE(
    crc32(result.subarray(4, 8 + data.byteLength)),
    8 + data.byteLength,
  );
  return result;
};

const webCapture = (
  artifact: WebScreenshotArtifact,
  targetId: string,
): Evidence =>
  createEvidence(undefined, CDP_PROVIDER, {
    predicateType: "rea.web-screenshot",
    operation: "capture_web_screenshot",
    parameters: { target_id: targetId },
    result: jsonValueSchema.parse({
      browser: {
        product: "Chrome/140.0.0.0",
        protocol_version: "1.3",
        revision: "fixture",
        user_agent: "fixture",
        js_version: "14.0",
      },
      target: {
        target_id: targetId,
        url: `http://127.0.0.1:8080/${targetId}`,
        origin: "http://127.0.0.1:8080",
      },
      captured_at: "2026-01-01T00:00:00.000Z",
      viewport: { width: SIZE, height: SIZE },
      artifact,
      completeness: classifyBrowserCompleteness({
        policyFilteredSections: new Set(),
        attachLimitedSections: new Set(),
        truncatedSections: new Set(),
        unavailableSections: new Set(),
        excluded: [],
        droppedEvents: {
          scripts: 0,
          network_requests: 0,
          console_events: 0,
          websocket_connections: 0,
          websocket_frames: 0,
          webmcp_tools: 0,
          timeline_events: 0,
        },
      }),
      limitations: [],
    }),
    confidence: "observed",
    authority: "external-service",
    environment: {
      id: "Chrome/140.0.0.0@fixture",
      platform: "unknown",
      architecture: "unknown",
      isolation: "none",
    },
  });

/** ADB screen capture; `artifact` embeds the opted-in inline PNG. */
const adbCapture = (
  bytes: Buffer,
  artifact: WebScreenshotArtifact | null = null,
): Evidence => {
  const capture = createWebScreenshotArtifact(bytes);
  return createEvidence(
    undefined,
    { id: "adb", name: "Android Debug Bridge", version: "fixture" },
    {
      predicateType: "rea.analysis",
      operation: "capture_adb_screen",
      parameters: {
        serial: "emulator-5554",
        include_artifact: artifact !== null,
      },
      result: jsonValueSchema.parse({
        client: {
          binary_path: "/usr/bin/adb",
          path_source: "path",
          version: null,
          installed_path: null,
        },
        serial: "emulator-5554",
        local_path: "/tmp/adb-capture/screen.png",
        bytes: capture.bytes,
        sha256: capture.sha256,
        width: SIZE,
        height: SIZE,
        ...(artifact === null ? {} : { artifact }),
      }),
      confidence: "observed",
      authority: "external-service",
    },
  );
};

const screenshotComparison = (
  before: WebScreenshotArtifact,
  after: WebScreenshotArtifact,
  channelThreshold = 0,
  override: (result: JsonValue) => JsonValue = (result) => result,
  identity: Partial<{
    confidence: "observed" | "derived";
    authority: "external-service" | "analyst-inference";
  }> = {},
): Evidence =>
  createEvidence(undefined, CDP_PROVIDER, {
    predicateType: "rea.web-screenshot-diff",
    operation: "compare_web_screenshots",
    parameters: {
      before_artifact_sha256: before.sha256,
      after_artifact_sha256: after.sha256,
      channel_threshold: channelThreshold,
    },
    result: override(
      jsonValueSchema.parse(
        comparePngScreenshots({
          before,
          after,
          channel_threshold: channelThreshold,
        }),
      ),
    ),
    confidence: identity.confidence ?? "observed",
    authority: identity.authority ?? "external-service",
  });

/** One original capture, one reconstruction capture, and their comparison. */
const fixture = (changed: readonly number[] = [5], channelThreshold = 0) => {
  const beforeArtifact = createWebScreenshotArtifact(png());
  const afterArtifact = createWebScreenshotArtifact(png(changed));
  const before = webCapture(beforeArtifact, "original");
  const after = webCapture(afterArtifact, "reconstruction");
  const comparison = screenshotComparison(
    beforeArtifact,
    afterArtifact,
    channelThreshold,
  );
  return { before, after, comparison, beforeArtifact, afterArtifact };
};

const visualSpec = (
  comparison: Evidence,
  before: Evidence,
  after: Evidence,
  claim: Partial<{
    channel_threshold: number;
    max_changed_ratio: number;
    mask: {
      rationale: string;
      regions: { x: number; y: number; width: number; height: number }[];
      max_masked_ratio: number;
    };
  }> = {},
) => ({
  name: "Screen parity",
  claims: [
    {
      kind: "visual" as const,
      claim_id: "home-screen",
      title: "Home screen renders like the original",
      comparison_evidence_id: comparison.evidence_id,
      dimension: "pixels" as const,
      before_evidence_id: before.evidence_id,
      after_evidence_id: after.evidence_id,
      channel_threshold: 0,
      max_changed_ratio: 0.1,
      ...claim,
    },
  ],
});

const verify = (
  spec: ReturnType<typeof visualSpec>,
  records: readonly Evidence[],
  unknowns: Parameters<typeof createEvidenceBundle>[1] = [],
) => verifyReconstruction(spec, createEvidenceBundle([...records], unknowns));

describe("visual claim outcomes", () => {
  it("passes when the recomputed changed ratio is within the declared bound", () => {
    const { before, after, comparison } = fixture([5]);
    const result = verify(visualSpec(comparison, before, after), [
      comparison,
      before,
      after,
    ]);
    expect(result).toMatchObject({
      status: "pass",
      summary: { total: 1, passed: 1, behavioral: 0, structural: 0, visual: 1 },
    });
    expect(result.claims.items[0]).toMatchObject({
      kind: "visual",
      dimension: "pixels",
      status: "pass",
      observed_status: "unchanged",
      left_evidence_ids: [before.evidence_id],
      right_evidence_ids: [after.evidence_id],
      visual: {
        channel_threshold: 0,
        max_changed_ratio: 0.1,
        compared_pixels: 16,
        changed_pixels: 1,
        changed_ratio: 1 / 16,
        masked_pixels: 0,
        recomputed: true,
      },
    });
    expect(result.evidence_links).toEqual(
      [comparison, before, after].map(({ evidence_id: id }) => id).sort(),
    );
  });

  it("fails when the changed ratio exceeds the declared bound", () => {
    const { before, after, comparison } = fixture([0, 1, 2, 3]);
    const result = verify(visualSpec(comparison, before, after), [
      comparison,
      before,
      after,
    ]);
    expect(result.status).toBe("fail");
    expect(result.claims.items[0]).toMatchObject({
      status: "fail",
      observed_status: "changed",
      visual: { changed_pixels: 4, changed_ratio: 0.25 },
    });
  });

  it("fails when the screenshots have different dimensions", () => {
    const beforeArtifact = createWebScreenshotArtifact(png());
    const afterArtifact = createWebScreenshotArtifact(png([], SIZE, SIZE + 1));
    const before = webCapture(beforeArtifact, "original");
    const after = webCapture(afterArtifact, "reconstruction");
    const comparison = screenshotComparison(beforeArtifact, afterArtifact);
    const result = verify(visualSpec(comparison, before, after), [
      comparison,
      before,
      after,
    ]);
    expect(result.claims.items[0]).toMatchObject({
      status: "fail",
      observed_status: "changed",
      visual: { compared_pixels: 0, changed_pixels: null, changed_ratio: null },
    });
  });

  it("stays unknown while an open unknown cites a source capture", () => {
    const { before, after, comparison } = fixture([5]);
    const mutation = createEvidence(
      undefined,
      { id: "fixture", name: "Fixture", version: "1" },
      {
        predicateType: "rea.residual-unknown-mutation",
        operation: "record_unknown",
        parameters: {},
        result: { action: "record" },
        confidence: "derived",
        authority: "analyst-inference",
        evidenceLinks: [after.evidence_id],
      },
    );
    const unknown = createResidualUnknown(
      {
        question: "Does the reconstruction render the same fonts?",
        severity: "medium",
        domain: "reconstruction-verification",
        supporting_evidence_ids: [after.evidence_id],
        contradicting_evidence_ids: [],
        required_authority: null,
        required_confidence: "observed",
        required_environment: null,
        recommended_probes: [],
        relationships: [],
      },
      mutation.evidence_id,
      null,
    );
    const result = verify(
      visualSpec(comparison, before, after),
      [comparison, before, after, mutation],
      [unknown],
    );
    expect(result.claims.items[0]).toMatchObject({
      status: "unknown",
      observed_status: "unchanged",
      unknown_ids: [unknown.unknown_id],
    });
  });
});

describe("visual claims over ADB captures", () => {
  /** Original ADB capture with retained pixels against a web reconstruction. */
  const adbFixture = (changed: readonly number[]) => {
    const beforeBytes = png();
    const beforeArtifact = createWebScreenshotArtifact(beforeBytes);
    const afterArtifact = createWebScreenshotArtifact(png(changed));
    return {
      before: adbCapture(beforeBytes, beforeArtifact),
      after: webCapture(afterArtifact, "reconstruction"),
      comparison: screenshotComparison(beforeArtifact, afterArtifact),
      beforeBytes,
      beforeArtifact,
    };
  };

  it("recomputes a pass from an ADB capture that retains its pixels", () => {
    const { before, after, comparison } = adbFixture([5]);
    const result = verify(visualSpec(comparison, before, after), [
      comparison,
      before,
      after,
    ]);
    expect(result.status).toBe("pass");
    expect(result.claims.items[0]).toMatchObject({
      status: "pass",
      observed_status: "unchanged",
      visual: { changed_pixels: 1, changed_ratio: 1 / 16, recomputed: true },
    });
  });

  it("recomputes a fail from an ADB capture that retains its pixels", () => {
    const { before, after, comparison } = adbFixture([0, 1, 2, 3]);
    const result = verify(visualSpec(comparison, before, after), [
      comparison,
      before,
      after,
    ]);
    expect(result.status).toBe("fail");
    expect(result.claims.items[0]).toMatchObject({
      status: "fail",
      observed_status: "changed",
      visual: { changed_pixels: 4, changed_ratio: 0.25, recomputed: true },
    });
  });

  it("rejects an ADB artifact that is not the PNG the capture reports", () => {
    const { after, comparison, beforeBytes } = adbFixture([5]);
    const other = createWebScreenshotArtifact(png([6]));
    const mismatched = adbCapture(beforeBytes, other);
    expect(() =>
      verify(visualSpec(comparison, mismatched, after), [
        comparison,
        mismatched,
        after,
      ]),
    ).toThrow("Screen capture artifact disagrees with the captured PNG");
  });

  it("rejects ADB inline bytes that disagree with their sealed digest", () => {
    const { after, comparison, beforeBytes, beforeArtifact } = adbFixture([5]);
    const forged = adbCapture(beforeBytes, {
      ...createWebScreenshotArtifact(png([6])),
      sha256: beforeArtifact.sha256,
      bytes: beforeArtifact.bytes,
    });
    expect(() =>
      verify(visualSpec(comparison, forged, after), [
        comparison,
        forged,
        after,
      ]),
    ).toThrow("Screenshot artifact digest or size mismatch");
  });
});

describe("visual claim limitations", () => {
  it("stays unknown when a source capture retains only its digest", () => {
    const beforeArtifact = createWebScreenshotArtifact(png());
    const afterBytes = png([5]);
    const afterArtifact = createWebScreenshotArtifact(afterBytes);
    const before = webCapture(beforeArtifact, "original");
    const after = adbCapture(afterBytes);
    const comparison = screenshotComparison(beforeArtifact, afterArtifact);
    const result = verify(visualSpec(comparison, before, after), [
      comparison,
      before,
      after,
    ]);
    expect(result.status).toBe("unknown");
    expect(result.claims.items[0]?.visual?.recomputed).toBe(false);
    expect(result.claims.items[0]?.limitations).toContain(
      `Source ${after.evidence_id} retains only its PNG digest; its pixels are unavailable in the Evidence bundle, so the comparison cannot be recomputed. Recapture ADB screens with include_artifact to retain them.`,
    );
    expect(result.recommended_probes).toMatchObject([
      { operation: "capture_web_screenshot", claim_ids: ["home-screen"] },
    ]);
  });

  it("stays unknown when the comparison used a different threshold", () => {
    const { before, after, comparison } = fixture([5], 0);
    const result = verify(
      visualSpec(comparison, before, after, { channel_threshold: 8 }),
      [comparison, before, after],
    );
    expect(result.status).toBe("unknown");
    expect(result.claims.items[0]?.limitations).toContain(
      "The comparison used channel threshold 0, not the declared 8.",
    );
  });

  it("stays unknown when one capture appears on both sides", () => {
    const artifact = createWebScreenshotArtifact(png());
    const capture = webCapture(artifact, "original");
    const comparison = screenshotComparison(artifact, artifact);
    const result = verify(visualSpec(comparison, capture, capture), [
      comparison,
      capture,
    ]);
    expect(result.status).toBe("unknown");
  });

  it("excludes declared mask regions from the decision ratio", () => {
    const { before, after, comparison } = fixture([0, 1, 4, 5]);
    const mask = {
      rationale: "Clock region renders the capture time",
      regions: [{ x: 0, y: 0, width: 2, height: 2 }],
      max_masked_ratio: 0.25,
    };
    const unmasked = verify(visualSpec(comparison, before, after), [
      comparison,
      before,
      after,
    ]);
    expect(unmasked.status).toBe("fail");
    const masked = verify(visualSpec(comparison, before, after, { mask }), [
      comparison,
      before,
      after,
    ]);
    expect(masked.claims.items[0]).toMatchObject({
      status: "pass",
      visual: {
        compared_pixels: 12,
        changed_pixels: 0,
        changed_ratio: 0,
        masked_pixels: 4,
      },
    });
    const tooLarge = verify(
      visualSpec(comparison, before, after, {
        mask: { ...mask, max_masked_ratio: 0.1 },
      }),
      [comparison, before, after],
    );
    expect(tooLarge.status).toBe("unknown");
    expect(tooLarge.claims.items[0]?.limitations).toContain(
      "The declared mask excludes 0.25 of the screenshot, more than its declared maximum 0.1.",
    );
    expect(() =>
      verify(
        visualSpec(comparison, before, after, {
          mask: { ...mask, regions: [{ x: 3, y: 3, width: 2, height: 1 }] },
        }),
        [comparison, before, after],
      ),
    ).toThrow("Visual mask region exceeds the compared screenshot");
    expect(
      reconstructionSpecificationSchema.safeParse(
        visualSpec(comparison, before, after, {
          mask: { ...mask, rationale: " " },
        }),
      ).success,
    ).toBe(false);
  });
});

describe("visual claim integrity", () => {
  it("rejects sources that are not the compared artifacts", () => {
    const { before, after, comparison } = fixture([5]);
    const other = webCapture(
      createWebScreenshotArtifact(png([6])),
      "reconstruction",
    );
    expect(() =>
      verify(visualSpec(comparison, before, other), [
        comparison,
        before,
        other,
      ]),
    ).toThrow(
      "Visual claim after source is not the artifact the comparison cites",
    );
    expect(() =>
      verify(visualSpec(comparison, after, before), [
        comparison,
        before,
        after,
      ]),
    ).toThrow(
      "Visual claim before source is not the artifact the comparison cites",
    );
  });

  it("rejects a source whose inline bytes disagree with its sealed digest", () => {
    const { before, after, comparison, afterArtifact } = fixture([5]);
    const tampered = createWebScreenshotArtifact(png([6]));
    const forged = webCapture(
      { ...tampered, sha256: afterArtifact.sha256 },
      "reconstruction",
    );
    expect(() =>
      verify(visualSpec(comparison, before, forged), [
        comparison,
        before,
        after,
        forged,
      ]),
    ).toThrow("Screenshot artifact digest or size mismatch");
  });

  it("rejects comparison metrics that the source pixels do not reproduce", () => {
    const { before, after, beforeArtifact, afterArtifact } = fixture([5]);
    const comparison = screenshotComparison(
      beforeArtifact,
      afterArtifact,
      0,
      (result) => ({
        ...(result as Record<string, JsonValue>),
        changed_pixels: 2,
        changed_ratio: 2 / 16,
      }),
    );
    expect(() =>
      verify(visualSpec(comparison, before, after), [
        comparison,
        before,
        after,
      ]),
    ).toThrow(
      "Screenshot comparison metrics disagree with its source artifacts",
    );
  });

  it("rejects comparisons outside the screenshot comparison identity", () => {
    const { before, after, beforeArtifact, afterArtifact } = fixture([5]);
    const comparison = screenshotComparison(
      beforeArtifact,
      afterArtifact,
      0,
      undefined,
      { confidence: "derived", authority: "analyst-inference" },
    );
    expect(() =>
      verify(visualSpec(comparison, before, after), [
        comparison,
        before,
        after,
      ]),
    ).toThrow("Comparison Evidence identity or authority disagrees");
  });
});
