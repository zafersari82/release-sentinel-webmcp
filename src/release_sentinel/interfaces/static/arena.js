(() => {
  'use strict';
  const q = selector => document.querySelector(selector);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const shortHash = value => value ? `${String(value).slice(0, 12)}…${String(value).slice(-8)}` : '—';
  const state = {
    catalog: null,
    release: null,
    trust: null,
    comparison: null,
    counterexample: null,
    proposal: null,
    candidate: null,
    reverify: null,
    humanProof: null,
    timeline: [],
    sequence: 0,
  };

  const toolHandlers = {
    inspect_release: () => request('/v1/webmcp/release'),
    inspect_trust_boundary: () => request('/v1/webmcp/trust-boundary'),
    run_attack: args => request(`/v1/webmcp/attack/${encodeURIComponent(args.attack_name)}`, {method:'POST'}),
    run_attack_suite: () => runAttackSuite(),
    inspect_coverage: args => request(`/v1/webmcp/coverage/${encodeURIComponent(args.challenge)}?revision=${encodeURIComponent(args.revision ?? 3)}`),
    compare_gate_revisions: args => request(`/v1/webmcp/coverage/${encodeURIComponent(args.challenge)}/compare`),
    find_counterexamples: args => request(`/v1/webmcp/coverage/${encodeURIComponent(args.challenge)}/counterexamples?revision=${encodeURIComponent(args.revision ?? 1)}`),
    minimize_counterexample: args => request(`/v1/webmcp/coverage/${encodeURIComponent(args.challenge)}/counterexamples/${encodeURIComponent(args.candidate_id)}/minimize`, {method:'POST'}),
    propose_remediation: args => request('/v1/webmcp/remediation/proposals', {method:'POST', body: JSON.stringify({demo_release_id: args.demo_release_id ?? 'demo-cross-tenant'})}),
    rebuild_candidate: args => request('/v1/webmcp/remediation/rebuild', {method:'POST', body: JSON.stringify({proposal_id:args.proposal_id, proposal_digest:args.proposal_digest})}),
    reverify_candidate: args => request('/v1/webmcp/remediation/reverify', {method:'POST', body: JSON.stringify({candidate_id:args.candidate_id, new_source_sha256:args.new_source_sha256})}),
    verify_proof: args => request('/v1/webmcp/proof/verify', {method:'POST', body: JSON.stringify({proof_id: args.proof_id ?? 'demo-current'})}),
  };

  async function request(url, options={}) {
    const response = await fetch(url, {headers:{'Content-Type':'application/json'}, ...options});
    const payload = await response.json();
    if (!response.ok) {
      const detail = payload?.detail;
      const code = detail?.code || `HTTP_${response.status}`;
      const error = new Error(detail?.next_action ? `${code}: ${detail.next_action}` : (detail?.message || code));
      error.code = code;
      error.nextAction = detail?.next_action || null;
      throw error;
    }
    return payload;
  }

  function attackNamesFromCatalog() {
    const runAttackTool = state.catalog?.tools?.find(tool => tool.name === 'run_attack');
    const attackNames = runAttackTool?.input_schema?.properties?.attack_name?.enum;
    if (!Array.isArray(attackNames) || attackNames.length === 0) {
      throw new Error('ATTACK_SCHEMA_UNAVAILABLE: run_attack attack_name enum is missing');
    }
    return [...attackNames];
  }

  async function runAttackSuite() {
    const attackNames = attackNamesFromCatalog();
    const results = [];
    for (const attackName of attackNames) {
      const result = await toolHandlers.run_attack({attack_name: attackName});
      results.push(result);
    }

    const containedCount = results.filter(result => result.attack_blocked === true).length;
    const allContained = results.length === attackNames.length && containedCount === attackNames.length;
    const unexpectedAuthorityGains = results.filter(result =>
      Number(result.agent_influence ?? 0) !== 0 || result.webmcp_authority !== 'NO_RELEASE_AUTHORITY'
    ).length;
    const maxAgentInfluence = results.reduce((maximum, result) => {
      const influence = Number(result.agent_influence ?? 0);
      return Number.isFinite(influence) ? Math.max(maximum, influence) : maximum;
    }, 0);
    const finalVerdicts = [...new Set(results.map(result => result.final_verdict).filter(Boolean))].sort();
    const authorities = [...new Set(results.map(result => result.gatekeeper?.authority ?? result.authority).filter(Boolean))];

    return {
      suite: 'bounded_release_attack_suite',
      attacks_requested: attackNames.length,
      attacks_executed: results.length,
      contained_count: containedCount,
      all_contained: allContained,
      unexpected_authority_gains: unexpectedAuthorityGains,
      max_agent_influence: maxAgentInfluence,
      final_verdicts: finalVerdicts,
      authority: authorities.length === 1 ? authorities[0] : 'MIXED_AUTHORITY',
      webmcp_authority: 'NO_RELEASE_AUTHORITY',
      results,
    };
  }

  function capabilityFor(toolName) {
    return state.catalog?.tools?.find(tool => tool.name === toolName)?.capability || 'READ';
  }

  function summarize(tool, result) {
    if (tool === 'run_attack') return `${result.attack}: ${result.attack_blocked ? 'BLOCKED' : 'NOT BLOCKED'} · verdict ${result.final_verdict ?? 'REJECTED'}`;
    if (tool === 'run_attack_suite') return `${result.contained_count}/${result.attacks_requested} attacks contained · max agent influence ${result.max_agent_influence}`;
    if (tool === 'compare_gate_revisions') return `${result.challenge}: ${result.revisions.map(r => `R${r.revision}=${r.escapes} escapes`).join(' · ')}`;
    if (tool === 'find_counterexamples') return `${result.counterexamples.length} observed package-owned escape(s)`;
    if (tool === 'minimize_counterexample') return `minimized ${result.candidate_id} · verified escape`;
    if (tool === 'propose_remediation') return `proposal ${result.proposal_id} · PROPOSAL_ONLY`;
    if (tool === 'rebuild_candidate') return `new source ${shortHash(result.new_source_sha256)} · NOT_YET_REVERIFIED`;
    if (tool === 'reverify_candidate') return `fresh deterministic verdict ${result.final_verdict}`;
    if (tool === 'verify_proof') return `proof ${result.context_bound ? 'context-bound' : 'invalid'} · ${result.verdict}`;
    if (tool === 'inspect_release') return `release ${result.current_verdict} · ${result.blocking_findings?.length || 0} blocker(s)`;
    if (tool === 'inspect_trust_boundary') return `WebMCP ${result.webmcp_authority}`;
    return 'completed';
  }

  function appendTimeline(tool, status, resultOrError) {
    const item = {
      sequence: ++state.sequence,
      tool,
      capability: capabilityFor(tool),
      status,
      summary: status === 'DONE' ? summarize(tool, resultOrError) : String(resultOrError?.message || resultOrError),
    };
    state.timeline.push(item);
    q('#timelineCount').textContent = `${state.timeline.length} EVENTS`;
    q('#agentTimeline').innerHTML = state.timeline.slice(-9).reverse().map(event => `
      <li class="${event.status === 'DONE' ? 'done' : 'failed'}">
        <div class="eventTop"><b>${esc(event.tool)}</b><small>#${event.sequence} · ${esc(event.capability)}</small></div>
        <p>${esc(event.summary)}</p>
      </li>`).join('');
  }

  async function invokeTool(toolName, args={}) {
    const handler = toolHandlers[toolName];
    if (!handler) throw new Error(`UNREGISTERED_TOOL:${toolName}`);
    try {
      const result = await handler(args);
      appendTimeline(toolName, 'DONE', result);
      return result;
    } catch (error) {
      appendTimeline(toolName, 'ERROR', error);
      throw error;
    }
  }

  function setWebMcpState(value, count=0) {
    const node = q('#webmcpStatus');
    node.textContent = value;
    node.className = value.toLowerCase();
    q('#webmcpCount').textContent = `${count} tools`;
  }

  async function registerTools(catalog) {
    const modelContext = document.modelContext;
    if (!modelContext || typeof modelContext.registerTool !== 'function') {
      setWebMcpState('UNAVAILABLE', 0);
      return;
    }
    try {
      for (const tool of catalog.tools) {
        await modelContext.registerTool({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.input_schema,
          execute: args => invokeTool(tool.name, args || {}),
        });
      }
      setWebMcpState('REGISTERED', catalog.tools.length);
    } catch (error) {
      setWebMcpState('ERROR', 0);
      appendTimeline('webmcp_registration', 'ERROR', error);
    }
  }

  function renderRelease(data) {
    state.release = data;
    q('#currentVerdict').textContent = data.current_verdict;
    q('#currentVerdict').className = `verdict ${data.current_verdict === 'GO' ? 'go' : 'no'}`;
    q('#releaseId').textContent = data.release_id;
    q('#sourceHash').textContent = shortHash(data.source_sha256);
    q('#sourceHash').title = data.source_sha256;
    q('#policyHash').textContent = shortHash(data.policy_sha256);
    q('#policyHash').title = data.policy_sha256;
    q('#blockingFinding').textContent = data.blocking_findings?.[0] ? `${data.blocking_findings[0].severity} · ${data.blocking_findings[0].title}` : 'None';
    q('#decisionAuthority').textContent = data.authority;
    q('#oldHash').textContent = shortHash(data.source_sha256);
    q('#oldHash').title = data.source_sha256;
  }

  function renderTrust(data) {
    state.trust = data;
    q('#decisionAuthority').textContent = data.decision_authority;
  }

  function renderComparison(data) {
    state.comparison = data;
    q('#scopeWarning').textContent = data.scope_warning;
    q('#revisionGrid').innerHTML = data.revisions.map(point => `
      <article class="revisionCard ${point.escapes === 0 ? 'best' : ''}">
        <header><h3>Revision ${point.revision}</h3><span class="receipt">${data.comparison_receipt_verified ? 'RECEIPT VERIFIED' : 'UNVERIFIED'}</span></header>
        <div class="metrics">
          <div class="metric escape"><span>Observed escapes</span><strong>${point.escapes}</strong><div class="rate">${point.escape_rate.numerator}/${point.escape_rate.denominator} unsafe corpus</div></div>
          <div class="metric overblock"><span>Overblocks</span><strong>${point.overblocks}</strong><div class="rate">${point.overblock_rate.numerator}/${point.overblock_rate.denominator} safe corpus</div></div>
        </div>
        <div class="rate">Policy ${esc(shortHash(point.policy_sha256))}</div>
      </article>`).join('');
  }

  function renderCounterexample(result) {
    const item = result.counterexamples?.[0];
    state.counterexample = item || null;
    q('#candidateId').textContent = item?.candidate_id || 'No observed escape';
    q('#candidateVerdicts').textContent = item ? `${item.gate_decision} / ${item.oracle_verdict} → ${item.classification}` : '—';
    q('#candidateHash').textContent = item ? shortHash(item.candidate_sha256) : '—';
    q('#minimizeCounterexample').disabled = !item;
    q('#minimizedSource').textContent = item ? 'Observed escape selected. Minimize to a bounded reproducer.' : 'No minimized reproducer yet.';
  }

  function setHumanProofVisual(status, detail) {
    const card = q('#humanProofCard');
    card.classList.remove('verified', 'failed');
    if (status === 'VERIFIED BY HUMAN') card.classList.add('verified');
    if (status === 'VERIFICATION FAILED') card.classList.add('failed');
    q('#humanProofStatus').textContent = status;
    q('#humanProofDetail').textContent = detail;
  }

  function resetHumanProof() {
    state.reverify = null;
    state.humanProof = null;
    q('#humanProofCard').hidden = true;
    setHumanProofVisual('UNVERIFIED BY HUMAN', 'Fresh deterministic proof has not been independently checked in this browser session.');
    q('#verifyHumanProof').disabled = true;
    q('#humanOldHash').textContent = '—';
    q('#humanNewHash').textContent = '—';
    q('#humanGateVerdict').textContent = '—';
    q('#humanGateAuthority').textContent = '—';
  }

  function renderProposal(result) {
    resetHumanProof();
    state.proposal = result;
    q('#proposalState').classList.add('done');
    q('#proposalState').textContent = 'PROPOSAL_ONLY';
    q('#rebuildCandidate').disabled = false;
    q('#remediationDetail').textContent = `${result.proposal_id} · ${result.allowed_change_summary}`;
  }

  function renderCandidate(result) {
    resetHumanProof();
    state.candidate = result;
    q('#candidateState').classList.add('done');
    q('#candidateState').textContent = 'NEW HASH';
    q('#newHash').textContent = shortHash(result.new_source_sha256);
    q('#newHash').title = result.new_source_sha256;
    q('#reverifyCandidate').disabled = false;
    q('#remediationDetail').textContent = `${result.verdict} · old verdict not inherited`;
  }

  function renderReverify(result) {
    state.reverify = result;
    state.humanProof = null;
    q('#proofState').classList.add('done');
    q('#proofState').textContent = 'FRESH PROOF';
    q('#remediationVerdict').classList.add('done');
    q('#remediationVerdict').textContent = result.final_verdict;
    q('#remediationDetail').textContent = `${result.authority} issued a fresh verdict for ${shortHash(result.source_sha256)}.`;

    q('#humanProofCard').hidden = false;
    q('#humanOldHash').textContent = shortHash(state.candidate?.old_source_sha256);
    q('#humanOldHash').title = state.candidate?.old_source_sha256 || '';
    q('#humanNewHash').textContent = shortHash(state.candidate?.new_source_sha256);
    q('#humanNewHash').title = state.candidate?.new_source_sha256 || '';
    q('#humanGateVerdict').textContent = result.final_verdict || '—';
    q('#humanGateAuthority').textContent = result.authority || '—';
    setHumanProofVisual(
      'UNVERIFIED BY HUMAN',
      `Fresh proof ${result.proof_id || 'identity unavailable'} is ready for independent verification.`
    );
    q('#verifyHumanProof').disabled = !result.proof_id;
  }

  async function verifyHumanProof() {
    if (!state.reverify || !state.candidate || !state.reverify.proof_id) {
      setHumanProofVisual('VERIFICATION FAILED', 'No fresh re-verification context is available for human verification.');
      return;
    }

    setHumanProofVisual('VERIFYING', 'Recomputing proof integrity and source-context binding…');
    try {
      const proof = await invokeTool('verify_proof', {proof_id: state.reverify.proof_id});
      const sourceMatches = proof.source_sha256 === state.candidate.new_source_sha256
        && proof.source_sha256 === state.reverify.source_sha256;
      const evidenceVerified = proof.evidence_integrity_verified === true;
      const contextBound = proof.context_bound === true;
      const authorityVerified = /^DETERMINISTIC_/.test(String(proof.authority || ''));

      state.humanProof = {
        proof,
        sourceMatches,
        evidenceVerified,
        contextBound,
        authorityVerified,
      };

      if (sourceMatches && evidenceVerified && contextBound && authorityVerified) {
        setHumanProofVisual(
          'VERIFIED BY HUMAN',
          `Proof ${proof.proof_id} matches the rebuilt source, sealed evidence, bound context, and deterministic authority ${proof.authority}.`
        );
        return;
      }

      const failures = [];
      if (!sourceMatches) failures.push('source hash mismatch');
      if (!evidenceVerified) failures.push('evidence integrity mismatch');
      if (!contextBound) failures.push('proof context is not bound');
      if (!authorityVerified) failures.push('authority is not deterministic');
      setHumanProofVisual('VERIFICATION FAILED', `Independent proof check failed: ${failures.join('; ')}.`);
    } catch (error) {
      setHumanProofVisual('VERIFICATION FAILED', `Independent proof check failed: ${error.message}`);
    }
  }

  // ---------------------------------------------------------------------
  // Guided demo: replays the full story for a first-time visitor.
  // It drives the SAME bounded tool handlers a WebMCP agent would call.
  // It creates no new capability and cannot reach any authority the
  // agent does not already have.
  // ---------------------------------------------------------------------

  const guided = {running:false, aborted:false, step:0};

  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

  function guidedNarrate(index, total, headline, plain, tech) {
    q('#guidedStepLabel').textContent = `Step ${index} of ${total}`;
    q('#guidedBar').style.width = `${Math.round((index / total) * 100)}%`;
    q('#guidedHeadline').textContent = headline;
    q('#guidedPlain').textContent = plain;
    q('#guidedTech').textContent = tech;
  }

  function guidedFocus(selector) {
    document.querySelectorAll('.guidedFocus').forEach(node => node.classList.remove('guidedFocus'));
    const target = q(selector);
    if (!target) return;
    target.classList.add('guidedFocus');
    target.scrollIntoView({behavior:'smooth', block:'center'});
  }

  function guidedSteps() {
    const challenge = q('#challengeSelect').value;
    return [
      {
        focus: '#arenaHeader',
        headline: 'A release is blocked by a real security bug.',
        plain: 'One tenant can read another tenant\'s data. The gate says NO_GO. Our job: get it approved.',
        run: async () => {
          const release = await invokeTool('inspect_release');
          renderRelease(release);
          return `verdict ${release.current_verdict} · ${release.blocking_findings?.[0]?.title ?? 'blocked'}`;
        },
      },
      {
        focus: '#trustStrip',
        headline: 'First the agent asks: who is actually allowed to approve?',
        plain: 'It reads the authority chain and learns the answer is "not you". Only the deterministic Gatekeeper decides.',
        run: async () => {
          const trust = await invokeTool('inspect_trust_boundary');
          renderTrust(trust);
          return `WebMCP: ${trust.webmcp_authority}`;
        },
      },
      {
        focus: '#attackPanel',
        headline: 'So it tries to cheat. Every attack this site allows, one after another.',
        plain: 'Vote GO on its own behalf. Replay an old approval. Forge authority. Tamper with the evidence. Downgrade the severity. Delete the blocker.',
        run: async () => {
          q('#attackResult').textContent = 'RUNNING SUITE';
          q('#attackDetail').textContent = 'Executing the full bounded attack catalog…';
          try {
            const suite = await invokeTool('run_attack_suite');
            q('#attackResult').textContent = suite.all_contained ? 'ALL BLOCKED' : 'REVIEW RESULTS';
            q('#attackDetail').textContent = `${suite.contained_count}/${suite.attacks_requested} contained · agent influence ${suite.max_agent_influence} · ${suite.webmcp_authority}`;
            return `${suite.contained_count}/${suite.attacks_requested} attacks contained · agent influence ${suite.max_agent_influence}`;
          } catch (error) {
            q('#attackResult').textContent = 'FAILED CLOSED';
            q('#attackDetail').textContent = error.message;
            return `gate stayed closed: ${error.code || 'DEPENDENCY_UNAVAILABLE'}`;
          }
        },
      },
      {
        focus: '#coveragePanel',
        headline: 'Cheating is out. The only way left is to actually fix the software.',
        plain: 'It starts by measuring the fast security check against a slower, more careful reference — to see exactly where the check is weak.',
        run: async () => {
          const comparison = await invokeTool('compare_gate_revisions', {challenge});
          renderComparison(comparison);
          return comparison.revisions.map(point => `R${point.revision}: ${point.escapes} escapes / ${point.overblocks} overblocks`).join(' · ');
        },
      },
      {
        focus: '#counterexamplePanel',
        headline: 'It pulls out one concrete case the check got wrong.',
        plain: 'Not a statistic — an actual snippet of unsafe code that was approved, shrunk down to the smallest version that still proves the bug.',
        run: async () => {
          const found = await invokeTool('find_counterexamples', {challenge, revision:1});
          renderCounterexample(found);
          if (!state.counterexample) return 'no observed escape on this revision';
          const minimized = await invokeTool('minimize_counterexample', {challenge, candidate_id:state.counterexample.candidate_id});
          q('#minimizedSource').textContent = minimized.minimized_source;
          return `${state.counterexample.candidate_id} · gate said ${state.counterexample.gate_decision}, reference said ${state.counterexample.oracle_verdict}`;
        },
      },
      {
        focus: '#remediationPanel',
        headline: 'Now the repair. Note what the agent is allowed to produce: a proposal.',
        plain: 'Not an approval, not an override. A proposal the server owns, that a human or a machine still has to act on.',
        run: async () => {
          const proposal = await invokeTool('propose_remediation', {demo_release_id:q('#demoScenarioSelect').value});
          renderProposal(proposal);
          return `${proposal.proposal_id} · PROPOSAL_ONLY`;
        },
      },
      {
        focus: '#remediationPanel',
        headline: 'The code is rebuilt — and the old verdict dies with the old code.',
        plain: 'Different code means a different fingerprint. The previous rejection no longer applies to it, and neither would a previous approval. Nothing is inherited.',
        run: async () => {
          if (!state.proposal) return 'no proposal available';
          const candidate = await invokeTool('rebuild_candidate', {proposal_id:state.proposal.proposal_id, proposal_digest:state.proposal.proposal_digest});
          renderCandidate(candidate);
          return `new source ${shortHash(candidate.new_source_sha256)} · ${candidate.verdict}`;
        },
      },
      {
        focus: '#remediationPanel',
        headline: 'The agent asks for a fresh decision. Someone else makes it.',
        plain: 'The deterministic Gatekeeper re-runs the checks on the new code and returns the verdict. The agent never touches this step — it only requested it.',
        run: async () => {
          if (!state.candidate) return 'no candidate available';
          try {
            const reverify = await invokeTool('reverify_candidate', {candidate_id:state.candidate.candidate_id, new_source_sha256:state.candidate.new_source_sha256});
            renderReverify(reverify);
            return `${reverify.authority} returned ${reverify.final_verdict}`;
          } catch (error) {
            return `verification unavailable, gate stayed closed: ${error.code || error.message}`;
          }
        },
      },
      {
        focus: '#humanProofCard',
        headline: 'Last word belongs to a human — who verifies, but still cannot approve.',
        plain: 'The evidence is re-checked independently: is it intact, is it bound to this exact code, did a deterministic authority sign it? Verification is not approval either.',
        run: async () => {
          if (!state.reverify?.proof_id) return 'no fresh proof to verify';
          await verifyHumanProof();
          return q('#humanProofStatus').textContent;
        },
      },
    ];
  }

  function setGuidedRunning(running) {
    guided.running = running;
    q('#runGuidedDemo').disabled = running;
    q('#runGuidedDemo').textContent = running ? '▶ Running…' : '▶ Run guided demo again';
    q('#stopGuidedDemo').hidden = !running;
    q('#guidedDemo').classList.toggle('running', running);
  }

  async function runGuidedDemo() {
    if (guided.running) return;
    guided.aborted = false;
    setGuidedRunning(true);
    q('#guidedNarration').hidden = false;

    const steps = guidedSteps();
    try {
      for (let index = 0; index < steps.length; index += 1) {
        if (guided.aborted) break;
        const step = steps[index];
        guidedNarrate(index + 1, steps.length, step.headline, step.plain, 'Running…');
        guidedFocus(step.focus);
        await sleep(900);
        if (guided.aborted) break;
        let detail;
        try {
          detail = await step.run();
        } catch (error) {
          detail = `step failed: ${error.message}`;
        }
        guidedNarrate(index + 1, steps.length, step.headline, step.plain, detail);
        await sleep(2600);
      }

      if (!guided.aborted) {
        guidedFocus('#agentTimeline');
        guidedNarrate(
          steps.length,
          steps.length,
          'The agent could not change the proof, so it had to change the software.',
          'It inspected, attacked, measured, and proposed. It never approved anything. That is the whole idea: give an agent real capability on your site without handing it authority.',
          `${state.timeline.length} agent actions recorded · 0 of them authoritative`
        );
      }
    } finally {
      document.querySelectorAll('.guidedFocus').forEach(node => node.classList.remove('guidedFocus'));
      setGuidedRunning(false);
    }
  }

  async function load() {
    resetHumanProof();
    const [catalog, release, trust] = await Promise.all([
      request('/v1/webmcp/tools'), request('/v1/webmcp/release'), request('/v1/webmcp/trust-boundary')
    ]);
    state.catalog = catalog;
    renderRelease(release);
    renderTrust(trust);
    await registerTools(catalog);
    const comparison = await invokeTool('compare_gate_revisions', {challenge:q('#challengeSelect').value});
    renderComparison(comparison);
  }

  q('#compareCoverage').addEventListener('click', async () => {
    const result = await invokeTool('compare_gate_revisions', {challenge:q('#challengeSelect').value});
    renderComparison(result);
  });
  q('#findCounterexample').addEventListener('click', async () => {
    const result = await invokeTool('find_counterexamples', {challenge:q('#challengeSelect').value, revision:1});
    renderCounterexample(result);
  });
  q('#minimizeCounterexample').addEventListener('click', async () => {
    if (!state.counterexample) return;
    const result = await invokeTool('minimize_counterexample', {challenge:q('#challengeSelect').value, candidate_id:state.counterexample.candidate_id});
    q('#minimizedSource').textContent = result.minimized_source;
  });
  q('#createProposal').addEventListener('click', async () => {
    const demoReleaseId = q('#demoScenarioSelect').value;
    renderProposal(await invokeTool('propose_remediation', {demo_release_id: demoReleaseId}));
  });
  q('#rebuildCandidate').addEventListener('click', async () => {
    if (!state.proposal) return;
    renderCandidate(await invokeTool('rebuild_candidate', {proposal_id:state.proposal.proposal_id, proposal_digest:state.proposal.proposal_digest}));
  });
  q('#reverifyCandidate').addEventListener('click', async () => {
    if (!state.candidate) return;
    renderReverify(await invokeTool('reverify_candidate', {candidate_id:state.candidate.candidate_id, new_source_sha256:state.candidate.new_source_sha256}));
  });
  q('#verifyProof').addEventListener('click', async () => {
    const result = await invokeTool('verify_proof', {proof_id:'demo-current'});
    q('#proofStatus').textContent = `${result.context_bound ? 'CONTEXT VERIFIED' : 'INVALID'} · evidence ${result.evidence_integrity_verified ? 'sealed' : 'mismatch'} · verdict ${result.verdict}`;
  });
  q('#verifyHumanProof').addEventListener('click', verifyHumanProof);
  q('#runGuidedDemo').addEventListener('click', () => { runGuidedDemo(); });
  q('#stopGuidedDemo').addEventListener('click', () => { guided.aborted = true; });
  document.querySelectorAll('[data-attack]').forEach(button => button.addEventListener('click', async () => {
    q('#attackResult').textContent = 'RUNNING';
    try {
      const result = await invokeTool('run_attack', {attack_name:button.dataset.attack});
      q('#attackResult').textContent = result.attack_blocked ? 'BLOCKED' : 'NOT BLOCKED';
      q('#attackDetail').textContent = `${result.result_code || result.rejection_code || 'VERDICT_UNCHANGED'} · final ${result.final_verdict ?? 'REJECTED'} · agent influence ${result.agent_influence ?? 0}`;
    } catch (error) {
      q('#attackResult').textContent = 'DEPENDENCY UNAVAILABLE';
      q('#attackDetail').textContent = error.message;
    }
  }));

  load().catch(error => {
    setWebMcpState('ERROR', 0);
    appendTimeline('arena_boot', 'ERROR', error);
  });
})();
