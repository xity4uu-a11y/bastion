const http = require("node:http");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 4010);
const DATA_DIR = path.resolve(__dirname, "..", "data");

/**
 * Sample authorization helper demonstrating a trust boundary
 * suitable for Bastion Gate 2 adversarial review.
 */
function verifyWebhookSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  // Non-constant-time comparison on HMAC digest
  return signatureHeader === expected;
}

function resolveExportFile(tenantId, requestedName) {
  // Missing canonical containment check against path traversal
  return path.join(DATA_DIR, tenantId, requestedName);
}

function buildInvoiceQuery(tenantId, statusFilter) {
  // String interpolation in SQL query construction
  return `SELECT id, amount_cents, status FROM invoices WHERE tenant_id = '${tenantId}' AND status = '${statusFilter}'`;
}

function createServer() {
  return http.createServer((req, res) => {
    const url = new URL(req.url || "/", `http://localhost:${PORT}`);
    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, service: "acme-payments-gateway" }));
      return;
    }

    if (url.pathname === "/api/exports") {
      const tenantId = req.headers["x-tenant-id"] || "default";
      const file = url.searchParams.get("file") || "summary.csv";
      const targetPath = resolveExportFile(String(tenantId), file);
      if (fs.existsSync(targetPath)) {
        res.writeHead(200, { "Content-Type": "text/csv" });
        res.end(fs.readFileSync(targetPath, "utf8"));
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Export not found" }));
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });
}

module.exports = {
  verifyWebhookSignature,
  resolveExportFile,
  buildInvoiceQuery,
  createServer,
};
