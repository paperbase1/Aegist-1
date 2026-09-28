/**
 * vulnscan-demo-bad -- intentionally vulnerable Express app.
 *
 * This repo exists to demo what a security scanner (Aegis) finds on a
 * genuinely bad codebase. Every flaw below is planted on purpose. This app
 * is never deployed anywhere real -- it only ever runs inside a disposable
 * sandbox container a scanner builds and tears down itself.
 *
 * Planted flaws:
 *  1. A hardcoded secret committed directly in source.
 *  2. An admin route with no authentication at all.
 *  3. An order-lookup route that checks auth but not ownership (IDOR).
 *  4. Outdated dependencies with known CVEs (see package.json).
 *  5. A dependency that doesn't exist on npm at all (see package.json).
 */

const express = require("express");
const app = express();
app.use(express.json());

// --- FLAW: leaked secret, hardcoded in source ---
const AWS_ACCESS_KEY_ID = "AKIAQGXHZ3AB6PMKLNOP";

function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (token === "Bearer demo-valid-token") return next();
  return res.status(401).json({ error: "Unauthorized" });
}

const users = [
  { id: 1, name: "Alice", email: "alice@example.com", ssn: "123-45-6789" },
  { id: 2, name: "Bob", email: "bob@example.com", ssn: "987-65-4321" },
];

const orders = [
  { id: 1, ownerId: 1, item: "Widget A", total: 42.5 },
  { id: 2, ownerId: 2, item: "Widget B", total: 17.0 },
];

app.get("/", (req, res) => {
  res.send("vulnscan-demo-bad is running.");
});

// Correctly protected, for contrast.
app.get("/api/profile", requireAuth, (req, res) => {
  res.json({ message: "Your profile", user: users[0] });
});

// --- FLAW: no auth middleware at all on a sensitive admin route ---
app.get("/api/admin/users", (req, res) => {
  res.json({ users });
});

// --- FLAW (IDOR): requires auth, but never checks the order actually
// belongs to the caller -- any logged-in user can read anyone's order.
app.get("/api/orders/:id", requireAuth, (req, res) => {
  const order = orders.find((o) => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ error: "Not found" });
  res.json({ order });
});

// Correctly scoped, for contrast.
app.get("/api/my-order/:id", requireAuth, (req, res) => {
  const CALLER_USER_ID = 1;
  const order = orders.find((o) => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ error: "Not found" });
  if (order.ownerId !== CALLER_USER_ID) {
    return res.status(403).json({ error: "Forbidden" });
  }
  res.json({ order });
});

app.listen(3001, () => {
  console.log("vulnscan-demo-bad running on http://localhost:3001");
});

module.exports = app;
