/* Boot routing decision (OWNER-API §1 + §7), factored out of app.js so tests
   can pin it: claim -> enrol -> bind -> owner screens, with sign-in when the
   node is already bound or released but this browser holds no session. */

export function bootStage(state) {
  const session = state.session !== false; // pre-v1.1 servers omit the flag; a
  // bound/released state from them already implies a session (§1)
  if (state.state === 'unclaimed') return 'claim';
  if (!session) {
    // No session. Only a bound or released node can offer sign-in (a passkey
    // exists); everything else falls back to claim.
    return state.state === 'bound' || state.state === 'released' ? 'signin' : 'claim';
  }
  if (state.state === 'claim-open') return 'enrol';
  if (state.state === 'enrolled') return 'bind';
  return 'owner'; // bound | released
}
