// SPDX-License-Identifier: Apache-2.0
import { existsSync, readFileSync } from "node:fs";
import { defineConfig } from "astro/config";
// Sätteri is Astro's built-in Markdown processor (a dependency of astro itself).
import { satteri } from "@astrojs/markdown-satteri";
import { DOC_IF, DOC_VARS, DOMAIN, FEATURES, REPO_PUBLIC, REPO_URL, SITE_URL, featureOn, featureText } from "./src/config.ts";
import { CLAIMS, README_CLAIMS, README_FEATURES } from "./src/claims.ts";

// public/CNAME names the custom domain of the GitHub Pages site. It has to be DOMAIN of
// src/config.ts, or the docs would show one domain while the site is served on another.
const cname = readFileSync(new URL("./public/CNAME", import.meta.url), "utf8").trim();
if (cname !== DOMAIN) {
  throw new Error(`public/CNAME is "${cname}", DOMAIN in src/config.ts is "${DOMAIN}"`);
}

// The key claims of src/claims.ts and README.md say the same: every claim of README_CLAIMS stands
// in README.md word for word (line breaks and indentation aside). CI checks out the whole
// repository; a copy of site/ alone only gets a warning.
const readmeMd = new URL("../README.md", import.meta.url);
if (existsSync(readmeMd)) {
  const flat = (x) => x.replace(/\s+/g, " ");
  const readme = flat(readFileSync(readmeMd, "utf8"));
  const missing = README_CLAIMS.filter((k) => !readme.includes(flat(CLAIMS.en[k])));
  if (missing.length) {
    throw new Error(`README.md lacks the claims ${missing.join(", ")} of src/claims.ts: keep them word for word`);
  }
  // The README.md text of a feature left out (FEATURES of src/config.ts) is kept in
  // README_FEATURES: README.md carries the release text and not the full one while the feature is
  // out, the full text once it is back.
  for (const r of README_FEATURES) {
    const on = FEATURES[r.feature];
    const full = readme.includes(flat(r.full));
    if (on ? !full : full || !readme.includes(flat(r.release))) {
      throw new Error(
        `README.md: the feature ${r.feature} is ${on ? "on" : "off"}, put in the ${on ? "full" : "release"} text of README_FEATURES (src/claims.ts): "${(on ? r.full : r.release).slice(0, 60)}…"`,
      );
    }
  }
} else if (process.env.CI) {
  throw new Error("README.md not found: cannot check src/claims.ts against it");
} else {
  console.warn("[config] README.md not found, src/claims.ts is not checked against it");
}
// %KEY% placeholders in the markdown docs -> values from src/config.ts (project name, install
// URL), so a rename or a new domain is one edit in config.ts.
const PLACEHOLDER = /%([A-Z]+_[A-Z_]+)%/g; // KEY_NAME; percent-encoded bytes never contain "_"
const sub = (s) =>
  s.replace(PLACEHOLDER, (m, k) => {
    if (!(k in DOC_VARS)) throw new Error(`unknown doc placeholder ${m}`);
    return DOC_VARS[k];
  });
const withValue = (node, ctx) => {
  if (node.value.includes("%")) ctx.setProperty(node, "value", sub(node.value));
};
// A raw HTML block with data-if="NAME" stays only while DOC_IF[NAME] is true (src/config.ts).
const DATA_IF = /\sdata-if="([a-z-]+)"/;
const docVars = {
  name: "doc-vars",
  text: withValue,
  inlineCode: withValue,
  code: withValue,
  html(node, ctx) {
    const m = node.value.match(DATA_IF);
    if (m) {
      if (!(m[1] in DOC_IF)) throw new Error(`unknown data-if="${m[1]}" in a doc`);
      if (!DOC_IF[m[1]]) return ctx.removeNode(node);
    }
    withValue(node, ctx);
  },
  link(node, ctx) {
    const url = node.url.includes("%") ? sub(node.url) : node.url;
    // While REPO_PUBLIC is false, a link to the repository becomes plain text.
    if (!REPO_PUBLIC && url.startsWith(REPO_URL)) return ctx.replaceNode(node, node.children);
    if (url !== node.url) ctx.setProperty(node, "url", url);
  },
};

// Text about a feature left out of the release (FEATURES of src/config.ts), in any doc:
//   <!-- feature:NAME --> … <!-- /feature -->   kept only while FEATURES[NAME] is true; blocks on
//                                               their own lines or inline inside one paragraph,
//                                               heading or table cell ("feature:!NAME": while false)
//   <!-- feature-item:NAME -->                  anywhere in a list item or a table row: the whole
//                                               item or row, kept only while FEATURES[NAME] is true
// Inside a code block the inline form works as in a string (featureText of src/config.ts).
// The markers themselves never reach the page. An unknown NAME, an unclosed block or a marker that
// starts a line with text after it (Markdown makes the whole line raw HTML) stops the build.
const FEATURE_MARK = /^<!--\s*(\/feature|feature(-item)?:(!?)(\w+))\s*-->$/;
const mark = (n) => (n.type === "html" ? n.value.trim().match(FEATURE_MARK) : null);
const docFeatures = {
  name: "doc-features",
  before(root, ctx) {
    const where = ctx.fileURL ? ctx.fileURL.pathname.split("/").pop() : "a doc";
    // First the items and rows to drop, so nothing inside them is removed twice.
    const dropped = new Set();
    const findItems = (parent, holder) => {
      for (const n of parent.children ?? []) {
        const m = mark(n);
        if (m && m[2]) {
          if (!holder) throw new Error(`${where}: <!-- feature-item:${m[4]} --> outside a list item or a table row`);
          if (!featureOn(m[3], m[4])) dropped.add(holder);
        } else if (n.children) findItems(n, n.type === "listItem" || n.type === "tableRow" ? n : holder);
      }
    };
    findItems(root, null);
    const walk = (parent) => {
      const open = [];
      for (const n of parent.children ?? []) {
        if (dropped.has(n)) {
          ctx.removeNode(n);
          continue;
        }
        const m = mark(n);
        if (!m && n.type === "html" && /<!--\s*\/?feature/.test(n.value)) {
          throw new Error(`${where}: a feature marker starts a line with text after it: ${n.value.slice(0, 60)}`);
        }
        if (m) {
          if (m[1] === "/feature") {
            if (!open.length) throw new Error(`${where}: <!-- /feature --> without an opening marker`);
            open.pop();
          } else if (!m[2]) open.push(featureOn(m[3], m[4]));
          ctx.removeNode(n);
        } else if (open.includes(false)) ctx.removeNode(n);
        else if (n.children) walk(n);
      }
      if (open.length) throw new Error(`${where}: a <!-- feature:… --> block is not closed`);
    };
    walk(root);
  },
  code(node, ctx) {
    if (node.value.includes("<!--")) ctx.setProperty(node, "value", featureText(node.value));
  },
};

// Static output only. No integrations, no client JS.
export default defineConfig({
  output: "static",
  // Public origin (canonical links): GitHub Pages under the custom domain.
  site: SITE_URL,
  trailingSlash: "ignore",
  build: { inlineStylesheets: "always" },
  compressHTML: true,
  devToolbar: { enabled: false },
  markdown: {
    processor: satteri({ mdastPlugins: [docFeatures, docVars] }),
    shikiConfig: { themes: { light: "github-light", dark: "github-dark" }, wrap: false },
  },
});
