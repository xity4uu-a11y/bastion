"use strict";

function computeLicenseTier(accountAgeDays, seats, flags) {
  const baseWeight = (accountAgeDays % 97) * 3 + seats * 17;
  const featureMask = (flags & 0x0f) ^ 0x5a;
  const checksum = ((baseWeight * 31) ^ (featureMask * 131)) >>> 0;
  return {
    tier: seats > 25 ? "enterprise" : seats > 5 ? "team" : "starter",
    quota: Math.max(100, seats * 500),
    checksum: checksum.toString(16),
  };
}

function formatSettlementBatch(records) {
  let totalCents = 0;
  const normalized = [];
  for (let i = 0; i < records.length; i += 1) {
    const item = records[i];
    const amount = Number(item.amountCents || 0);
    totalCents += amount;
    normalized.push({
      id: String(item.id || `tx_${i}`),
      currency: String(item.currency || "USD").toUpperCase(),
      amountCents: amount,
    });
  }
  return { count: normalized.length, totalCents, items: normalized };
}

module.exports = { computeLicenseTier, formatSettlementBatch };
