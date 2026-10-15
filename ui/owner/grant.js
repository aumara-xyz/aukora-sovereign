/* Grant math + client-side validation (OWNER-API §8). Dollars in the UI,
   canonical integer microusd on the wire. Zero, negative and over-24h values
   are refused here (broker:invalid-grant) before any proposal is made; the
   server refuses them again. */

export const MICRO = 1_000_000;

export function usdToMicro(usd) {
  const n = Number(usd);
  if (!Number.isFinite(n) || n <= 0) return null;
  const micro = Math.round(n * MICRO);
  return micro > 0 ? micro : null;
}

export function microToUsd(micro) {
  return (micro / MICRO).toFixed(2);
}

/* Returns the wire body for /api/broker/grant/propose or throws
   broker:invalid-grant. */
export function validateGrant({ model, capUsd, perRequestUsd, maxRequests, hours }, models) {
  const fail = () => { throw Object.assign(new Error('broker:invalid-grant'), { code: 'broker:invalid-grant' }); };
  if (!Array.isArray(models) || !models.includes(model)) fail();
  const cap_microusd = usdToMicro(capUsd);
  const per_request_cap_microusd = usdToMicro(perRequestUsd);
  const max_requests = Number(maxRequests);
  const h = Number(hours);
  if (cap_microusd === null || per_request_cap_microusd === null) fail();
  if (!Number.isInteger(max_requests) || max_requests < 1) fail();
  if (!Number.isInteger(h) || h < 1 || h > 24) fail();
  return { model, cap_microusd, per_request_cap_microusd, max_requests, hours: h };
}
