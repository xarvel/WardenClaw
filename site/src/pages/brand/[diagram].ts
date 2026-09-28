// SPDX-License-Identifier: Apache-2.0
// The diagrams of src/brand/ at /brand/<name>.svg, with the text of the features left out of the
// release taken out: <!-- feature:NAME --> spans, as in the docs (src/config.ts, FEATURES).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { APIRoute } from "astro";
import { featureText } from "../../config";

const DIAGRAMS = ["architecture.en.svg", "lifecycle.en.svg"];

export const getStaticPaths = () => DIAGRAMS.map((diagram) => ({ params: { diagram } }));

export const GET: APIRoute = ({ params }) =>
  new Response(featureText(readFileSync(join(process.cwd(), "src", "brand", String(params.diagram)), "utf8")), {
    headers: { "Content-Type": "image/svg+xml" },
  });
