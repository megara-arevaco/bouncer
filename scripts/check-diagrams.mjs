import { readFile, readdir } from "node:fs/promises";
import { chromium } from "@playwright/test";
import { createServer } from "vite";

// Render the actual Markdown blocks in Chromium, including Mermaid's layout.
const files = ["README.md", ...(await readdir("docs"))
  .filter((name) => name.endsWith(".md")).map((name) => `docs/${name}`)];
const server = await createServer({ configFile: false, logLevel: "error",
  server: { host: "127.0.0.1", port: 0 }, appType: "custom" });
server.middlewares.use("/diagram-check", (_req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.end('<!doctype html><html><body><div id="drawing"></div></body></html>');
});
let browser;
let count = 0;
try {
  await server.listen();
  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/diagram-check`);
  await page.evaluate(async () => {
    const { default: mermaid } = await import("/node_modules/mermaid/dist/mermaid.esm.min.mjs");
    mermaid.initialize({ startOnLoad: false, securityLevel: "strict" });
    window.mermaid = mermaid;
  });
  for (const file of files) {
    const markdown = await readFile(file, "utf8");
    for (const match of markdown.matchAll(/```mermaid\s*\n([\s\S]*?)```/g)) {
      count++;
      try {
        await page.evaluate(async ({ source, id }) => {
          const { svg } = await window.mermaid.render(id, source);
          document.querySelector("#drawing").innerHTML = svg;
          const box = document.querySelector("#drawing svg").getBoundingClientRect();
          if (box.width <= 0 || box.height <= 0) throw new Error("Empty diagram");
        }, { source: match[1], id: `diagram${count}` });
      } catch (error) {
        throw new Error(`${file}, Mermaid block ${count}: ${error.message}`);
      }
    }
  }
  if (!count) throw new Error("No Mermaid diagrams found.");
  console.log(`Rendered ${count} Mermaid diagrams successfully.`);
} finally {
  await browser?.close();
  await server.close();
}
