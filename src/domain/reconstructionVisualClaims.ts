import { z } from "zod";

import { adbResultSchemas } from "./adb/adbDeviceAnalysis.js";
import { uniqueSorted } from "./canonicalOrdering.js";
import type { Evidence } from "./evidence.js";
import type {
  ReconstructionClaim,
  ReconstructionClaimResult,
  ReconstructionObservedStatus,
} from "./reconstructionVerificationSchemas.js";
import {
  webScreenshotDiffSchema,
  webScreenshotSchema,
  type WebScreenshotArtifact,
  type WebScreenshotDiff,
} from "./webScreenshot.js";
import { measurePngScreenshots } from "./webScreenshotPixels.js";

type VisualClaim = Extract<ReconstructionClaim, { kind: "visual" }>;
type Side = "before" | "after";

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const screenshotComparisonParametersSchema = z.object({
  before_artifact_sha256: sha256Schema,
  after_artifact_sha256: sha256Schema,
  channel_threshold: z.number().int().min(0).max(255),
});

interface ScreenshotSource {
  readonly evidence: Evidence;
  readonly sha256: string;
  /** Inline pixels; null when the capture retains only its digest. */
  readonly artifact: WebScreenshotArtifact | null;
  readonly dimensions: {
    readonly width: number;
    readonly height: number;
  } | null;
}

/** Facts a visual claim contributes to the shared claim classification. */
export interface VisualClaimFacts {
  readonly sides: { readonly left: string[]; readonly right: string[] };
  readonly sourceIds: string[];
  readonly observed: ReconstructionObservedStatus;
  readonly limitations: string[];
  readonly visual: NonNullable<ReconstructionClaimResult["visual"]>;
}

/**
 * Bind a screenshot comparison to its declared capture Evidence, recompute it
 * from the retained pixels, and apply the declared threshold and mask.
 */
export const visualClaimFacts = (
  claim: VisualClaim,
  comparison: Evidence,
  records: ReadonlyMap<string, Evidence>,
): VisualClaimFacts => {
  const diff = webScreenshotDiffSchema.parse(comparison.normalized_result);
  const parameters = screenshotComparisonParametersSchema.parse(
    comparison.parameters,
  );
  if (parameters.channel_threshold !== diff.channel_threshold)
    throw new TypeError(
      "Screenshot comparison threshold disagrees with its parameters",
    );
  const before = boundSource(
    records,
    claim.before_evidence_id,
    parameters.before_artifact_sha256,
    diff,
    "before",
  );
  const after = boundSource(
    records,
    claim.after_evidence_id,
    parameters.after_artifact_sha256,
    diff,
    "after",
  );
  const limitations: string[] = [];
  if (before.evidence.evidence_id === after.evidence.evidence_id)
    limitations.push(
      "A source observation appears on both comparison sides; independent original and reconstruction observations are unavailable.",
    );
  for (const source of [before, after]) {
    if (source.evidence.confidence !== "observed")
      limitations.push(
        `Source ${source.evidence.evidence_id} is not an observed screenshot capture.`,
      );
    if (source.artifact === null)
      limitations.push(
        `Source ${source.evidence.evidence_id} retains only its PNG digest; its pixels are unavailable in the Evidence bundle, so the comparison cannot be recomputed. Recapture ADB screens with include_artifact to retain them.`,
      );
  }
  if (claim.channel_threshold !== diff.channel_threshold)
    limitations.push(
      `The comparison used channel threshold ${diff.channel_threshold}, not the declared ${claim.channel_threshold}.`,
    );
  const regions = claim.mask?.regions ?? [];
  if (diff.status !== "dimension_mismatch")
    for (const region of regions)
      if (
        region.x + region.width > diff.before.width ||
        region.y + region.height > diff.before.height
      )
        throw new TypeError(
          "Visual mask region exceeds the compared screenshot",
        );

  let measured: {
    compared_pixels: number;
    changed_pixels: number | null;
    masked_pixels: number;
  } = {
    compared_pixels: diff.compared_pixels,
    changed_pixels: regions.length === 0 ? diff.changed_pixels : null,
    masked_pixels: 0,
  };
  let recomputed = false;
  if (before.artifact !== null && after.artifact !== null) {
    const measurement = measurePngScreenshots(
      {
        before: before.artifact,
        after: after.artifact,
        channel_threshold: diff.channel_threshold,
      },
      regions,
    );
    if (metricKey(measurement.diff) !== metricKey(diff))
      throw new TypeError(
        "Screenshot comparison metrics disagree with its source artifacts",
      );
    if (measurement.masked !== null) measured = { ...measurement.masked };
    recomputed = true;
  }
  if (claim.mask !== undefined && recomputed && diff.compared_pixels > 0) {
    const maskedRatio = measured.masked_pixels / diff.compared_pixels;
    if (measured.compared_pixels === 0)
      limitations.push("The declared mask excludes every compared pixel.");
    else if (maskedRatio > claim.mask.max_masked_ratio)
      limitations.push(
        `The declared mask excludes ${maskedRatio} of the screenshot, more than its declared maximum ${claim.mask.max_masked_ratio}.`,
      );
  }
  const changedRatio =
    measured.changed_pixels === null || measured.compared_pixels === 0
      ? null
      : measured.changed_pixels / measured.compared_pixels;
  const observed: ReconstructionObservedStatus =
    diff.status === "dimension_mismatch"
      ? "changed"
      : changedRatio === null
        ? "unknown"
        : changedRatio > claim.max_changed_ratio
          ? "changed"
          : "unchanged";
  const sides = {
    left: [before.evidence.evidence_id],
    right: [after.evidence.evidence_id],
  };
  return {
    sides,
    sourceIds: uniqueSorted([...sides.left, ...sides.right]),
    observed,
    limitations,
    visual: {
      channel_threshold: diff.channel_threshold,
      max_changed_ratio: claim.max_changed_ratio,
      compared_pixels: measured.compared_pixels,
      changed_pixels: measured.changed_pixels,
      changed_ratio: changedRatio,
      masked_pixels: measured.masked_pixels,
      recomputed,
    },
  };
};

const boundSource = (
  records: ReadonlyMap<string, Evidence>,
  evidenceId: string,
  comparedSha256: string,
  diff: WebScreenshotDiff,
  side: Side,
): ScreenshotSource => {
  const evidence = records.get(evidenceId);
  if (evidence === undefined)
    throw new TypeError(`Missing source Evidence ${evidenceId}`);
  const source = readScreenshotSource(evidence);
  if (source.sha256 !== comparedSha256)
    throw new TypeError(
      `Visual claim ${side} source is not the artifact the comparison cites`,
    );
  if (
    source.dimensions !== null &&
    (source.dimensions.width !== diff[side].width ||
      source.dimensions.height !== diff[side].height)
  )
    throw new TypeError(
      `Visual claim ${side} source dimensions disagree with the comparison`,
    );
  return source;
};

const readScreenshotSource = (evidence: Evidence): ScreenshotSource => {
  if (
    evidence.operation === "capture_web_screenshot" &&
    evidence.predicate_type === "rea.web-screenshot"
  ) {
    // The artifact schema verifies the inline bytes against their sealed digest.
    const { artifact } = webScreenshotSchema.parse(evidence.normalized_result);
    return { evidence, sha256: artifact.sha256, artifact, dimensions: null };
  }
  if (
    evidence.operation === "capture_adb_screen" &&
    evidence.predicate_type === "rea.analysis"
  ) {
    // The capture schema binds an opted-in artifact to the reported digest
    // and size; the artifact schema verifies the inline bytes against both.
    const capture = adbResultSchemas.capture_adb_screen.parse(
      evidence.normalized_result,
    );
    return {
      evidence,
      sha256: capture.sha256,
      artifact: capture.artifact ?? null,
      dimensions:
        capture.width === null || capture.height === null
          ? null
          : { width: capture.width, height: capture.height },
    };
  }
  throw new TypeError(
    "Visual claim source Evidence is not a screenshot capture",
  );
};

const metricKey = (diff: WebScreenshotDiff): string =>
  JSON.stringify([
    diff.status,
    diff.before,
    diff.after,
    diff.channel_threshold,
    diff.compared_pixels,
    diff.changed_pixels,
    diff.changed_ratio,
    diff.maximum_channel_delta,
    diff.mean_absolute_channel_delta,
  ]);
