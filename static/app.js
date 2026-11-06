const $ = (id) => document.getElementById(id);
let selectedFile = null;
let activeJob = null;
let latestJob = null;
let pollTimer = null;
let pollFailures = 0;

const TERMINAL_STATUSES = new Set(['completed', 'completed_with_errors', 'failed']);
const ACTIVE_JOB_KEY = 'cultive8.activeJobId';

function storeActiveJob(jobId) {
  try { if (jobId) localStorage.setItem(ACTIVE_JOB_KEY, jobId); else localStorage.removeItem(ACTIVE_JOB_KEY); } catch { /* Storage can be disabled; live polling still works. */ }
}

function readStoredJob() {
  try {
    const value = localStorage.getItem(ACTIVE_JOB_KEY);
    return value && /^[a-f0-9]{32}$/i.test(value) ? value : null;
  } catch { return null; }
}

async function refreshHealth() {
  try {
    const response = await fetch('/api/health', { cache: 'no-store' });
    if (!response.ok) throw new Error('Health check failed');
    const data = await response.json();
    $('modelState').textContent = data.model_status === 'ready' ? 'MODEL READY' : 'MODEL OFFLINE';
    $('modelState').style.color = data.model_status === 'ready' ? '#9be4bd' : '#ffb36b';
  } catch {
    $('modelState').textContent = 'BACKEND OFFLINE';
    $('modelState').style.color = '#ff7777';
  }
}

function setFile(file) {
  if (!file) return;
  const ext = file.name.toLowerCase().split('.').pop();
  if (!['log', 'txt'].includes(ext)) {
    alert('Please choose a .log or .txt file.');
    return;
  }
  if (file.size > 25 * 1024 * 1024) {
    alert('The maximum upload size is 25 MB.');
    return;
  }
  selectedFile = file;
  $('fileTitle').textContent = file.name;
  $('fileSub').textContent = `${(file.size / 1024).toFixed(1)} KB · Ready to analyze`;
  $('filePill').hidden = false;
  $('filePill').textContent = file.name;
  $('analyzeBtn').disabled = false;
}

$('logFile').addEventListener('change', e => setFile(e.target.files[0]));
$('dropzone').addEventListener('dragover', e => { e.preventDefault(); $('dropzone').classList.add('dragover'); });
$('dropzone').addEventListener('dragleave', () => $('dropzone').classList.remove('dragover'));
$('dropzone').addEventListener('drop', e => {
  e.preventDefault();
  $('dropzone').classList.remove('dragover');
  setFile(e.dataTransfer.files[0]);
});

$('analyzeBtn').addEventListener('click', async () => {
  if (!selectedFile || activeJob) return;
  $('analyzeBtn').disabled = true;
  $('progressPanel').hidden = false;
  $('reportSection').hidden = true;
  $('errorBox').hidden = true;
  $('chunkActivity').hidden = true;
  setStatus('UPLOADING', 'running');
  $('progressTitle').textContent = 'Uploading log securely';
  $('progressText').textContent = selectedFile.name;
  setProgress(3, false);
  updatePipeline('tokenizing', 'queued', 0);

  try {
    const body = new FormData();
    body.append('file', selectedFile);
    const response = await fetch('/api/analyze', { method: 'POST', body });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Upload failed.');
    activeJob = data.job_id;
    storeActiveJob(activeJob);
    pollFailures = 0;
    setStatus('QUEUED', 'running');
    $('progressTitle').textContent = 'Analysis queued';
    $('progressText').textContent = 'Waiting for the local inference worker';
    schedulePoll(300);
  } catch (error) {
    showError(error.message);
    $('analyzeBtn').disabled = false;
    activeJob = null;
  }
});

function schedulePoll(delay = 1500) {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(pollJob, delay);
}

async function pollJob() {
  if (!activeJob) return;
  try {
    const response = await fetch(`/api/jobs/${activeJob}`, { cache: 'no-store' });
    const job = await response.json();
    if (!response.ok) {
      if (response.status === 404) throw Object.assign(new Error(job.detail || 'Analysis job no longer exists.'), { permanent: true });
      throw new Error(job.detail || `Status request failed (${response.status}).`);
    }
    pollFailures = 0;
    latestJob = job;
    renderJobProgress(job);

    if (TERMINAL_STATUSES.has(job.status)) {
      activeJob = null;
      storeActiveJob(null);
      if (pollTimer) clearTimeout(pollTimer);
      pollTimer = null;
      $('analyzeBtn').disabled = false;
      if (job.status !== 'failed') renderReport(job);
      return;
    }
    schedulePoll(1500);
  } catch (error) {
    pollFailures += 1;
    if (error.permanent) {
      showError(error.message);
      activeJob = null;
      storeActiveJob(null);
      if (pollTimer) clearTimeout(pollTimer);
      pollTimer = null;
      $('analyzeBtn').disabled = false;
      return;
    }
    setStatus('RECONNECTING', 'warning');
    $('progressTitle').textContent = 'Connection interrupted';
    $('progressText').textContent = `The job may still be running. Reconnecting (attempt ${pollFailures}); polling will continue.`;
    $('phaseText').textContent = 'Waiting for backend response';
    schedulePoll(Math.min(15000, 1500 * (1 + pollFailures)));
  }
}

function setStatus(label, state) {
  const chip = $('statusChip');
  chip.textContent = label;
  chip.className = `status-chip ${state || ''}`.trim();
}

function setProgress(percent, indeterminate) {
  const track = $('progressBar').parentElement;
  track.classList.toggle('indeterminate', Boolean(indeterminate));
  $('progressBar').style.width = `${Math.max(0, Math.min(100, percent))}%`;
}

function humanPhase(phase) {
  if (!phase) return 'Waiting';
  if (phase === 'tokenizing') return 'Parsing and tokenizing';
  if (phase === 'correlating') return 'Correlating and reviewing source candidates';
  const reviewMatch = phase.match(/^reviewing_candidate_(\d+)_of_(\d+)$/);
  if (reviewMatch) return `Local AI candidate review ${reviewMatch[1]} of ${reviewMatch[2]}`;
  if (phase === 'generating_report') return 'Building evidence report';
  if (phase === 'complete') return 'Analysis complete';
  if (phase === 'model_unavailable') return 'Local model unavailable';
  if (phase === 'analysis_error') return 'Analysis failed';
  const match = phase.match(/^analyzing_chunk_(\d+)$/);
  if (match) return `Analyzing chunk ${match[1]}`;
  return phase.replaceAll('_', ' ');
}

function updatePipeline(phase, status, processed) {
  const steps = [...document.querySelectorAll('[data-pipeline-step]')];
  const states = ['pending', 'pending', 'pending', 'pending'];
  const isTerminal = TERMINAL_STATUSES.has(status);
  const chunkPhase = /^analyzing_chunk_\d+$/.test(phase || '');

  if (phase === 'tokenizing' || status === 'queued') {
    states[0] = 'active';
  } else if (chunkPhase || (phase || '').startsWith('analyzing_')) {
    states[0] = 'complete';
    states[1] = 'active';
  } else if (phase === 'correlating' || (phase || '').startsWith('reviewing_candidate_')) {
    states[0] = 'complete'; states[1] = 'complete'; states[2] = 'active';
  } else if (phase === 'generating_report') {
    states[0] = 'complete'; states[1] = 'complete'; states[2] = 'complete'; states[3] = 'active';
  } else if (phase === 'complete' || status === 'completed' || status === 'completed_with_errors') {
    states.fill('complete');
    if (status === 'completed_with_errors') states[1] = 'warning';
  } else if (status === 'failed') {
    if (phase === 'model_unavailable') states[1] = 'error';
    else if (phase === 'analysis_error') states[Math.min(3, processed > 0 ? 1 : 0)] = 'error';
    else states[0] = 'error';
  }

  steps.forEach((step, index) => {
    const state = states[index];
    step.classList.remove('active', 'complete', 'warning', 'error');
    if (state !== 'pending') step.classList.add(state);
    const label = step.querySelector('.step-status');
    if (label) {
      label.textContent = ({ pending: 'WAITING', active: 'IN PROGRESS', complete: 'COMPLETE', warning: 'REVIEW', error: 'FAILED' })[state];
    }
    step.setAttribute('aria-current', state === 'active' ? 'step' : 'false');
  });

  document.querySelectorAll('[data-pipeline-line]').forEach((line, index) => {
    line.classList.toggle('complete', states[index] === 'complete' && states[index + 1] !== 'pending');
  });
}

function renderChunkActivity(job) {
  const chunks = job.chunks || [];
  const realChunks = chunks.filter(x => !String(x.status).startsWith('final_correlation'));
  const successful = job.completed_chunks ?? realChunks.filter(x => x.status === 'completed').length;
  const failed = job.failed_chunks ?? realChunks.filter(x => x.status === 'failed').length;
  $('chunkCount').textContent = `${job.processed_chunks || 0} attempted · ${successful} OK · ${failed} failed`;
  $('chunkOutcomeCount').textContent = `${successful} succeeded · ${failed} failed`;
  $('chunkActivity').hidden = realChunks.length === 0;

  const tbody = $('chunkRows');
  tbody.replaceChildren();
  realChunks.slice(-6).reverse().forEach(chunk => {
    const row = document.createElement('tr');
    const label = chunk.status === 'completed' ? 'Complete' : chunk.status === 'failed' ? 'Failed' : chunk.status;
    const statusClass = chunk.status === 'completed' ? 'ok' : chunk.status === 'failed' ? 'bad' : 'pending';
    const values = [
      `#${chunk.chunk_index}`,
      `L${chunk.start_line}–${chunk.end_line}`,
      label,
      chunk.model_ms ? `${(chunk.model_ms / 1000).toFixed(1)}s` : '—',
      chunk.error || (chunk.prompt_tokens ? `${chunk.prompt_tokens} prompt tokens` : 'In progress')
    ];
    values.forEach((value, index) => {
      const cell = document.createElement('td');
      cell.textContent = value;
      if (index === 2) cell.className = `chunk-status ${statusClass}`;
      if (index === 4 && chunk.error) cell.className = 'chunk-error-detail';
      row.append(cell);
    });
    tbody.append(row);
  });
}

function renderJobProgress(job) {
  const phase = job.phase || job.status;
  const done = TERMINAL_STATUSES.has(job.status);
  const failed = job.status === 'failed';
  const chunks = job.processed_chunks || 0;
  updatePipeline(phase, job.status, chunks);
  renderChunkActivity(job);
  setProgress(done ? 100 : (chunks ? 65 : 8), !done);
  $('phaseText').textContent = humanPhase(phase);
  $('progressTitle').textContent = failed ? 'Analysis stopped' : job.status === 'completed_with_errors' ? 'Analysis completed with warnings' : done ? 'Analysis complete' : 'Analyzing log records';
  $('progressText').textContent = `${job.filename} · ${job.findings_count || 0} evidence-backed finding(s)`;
  setStatus(job.status.toUpperCase().replaceAll('_', ' '), failed ? 'error' : job.status === 'completed_with_errors' ? 'warning' : done ? 'success' : 'running');
  const created = Date.parse(job.created_at || '');
  if (Number.isFinite(created)) {
    const seconds = Math.max(0, Math.floor((Date.now() - created) / 1000));
    const mm = String(Math.floor(seconds / 60)).padStart(2, '0');
    const ss = String(seconds % 60).padStart(2, '0');
    $('elapsedText').textContent = `Elapsed ${mm}:${ss} · sequential`;
  }
  if (job.error) showError(job.error);
  else if (!done) $('errorBox').hidden = true;
}

function showError(message) {
  $('errorBox').hidden = false;
  $('errorBox').textContent = message;
}

function renderReport(job) {
  const findings = job.findings || [];
  const report = job.report || {};
  $('reportSection').hidden = false;
  $('statFindings').textContent = findings.length;
  $('statHigh').textContent = findings.filter(x => ['High', 'Critical'].includes(x.severity)).length;
  $('statChunks').textContent = report.chunks_processed ?? job.processed_chunks ?? 0;
  $('statLines').textContent = report.total_lines ?? report.summary?.match(/Analyzed (\d+) source lines/)?.[1] ?? '—';
  $('reportSummary').textContent = report.summary || `Analysis completed for ${job.filename}.`;

  const aiSummary = $('aiReviewSummary');
  if (report.candidate_review_attempted !== undefined) {
    const attempted = report.candidate_review_attempted || 0;
    const reviewed = report.candidate_review_succeeded || 0;
    const failedReviews = report.candidate_review_failed || 0;
    const confirmed = report.ai_corroborated_findings || 0;
    const ruleOnly = report.rule_only_findings ?? Math.max(0, findings.length - confirmed);
    aiSummary.hidden = false;
    aiSummary.textContent = `SOURCE RULE CANDIDATES: ${report.rule_based_findings ?? findings.length} · AI REVIEWS: ${reviewed}/${attempted} completed · AI-CORROBORATED: ${confirmed} · RULE-ONLY: ${ruleOnly}${failedReviews ? ` · REVIEW ERRORS: ${failedReviews}` : ''}`;
  } else {
    aiSummary.hidden = true;
    aiSummary.textContent = '';
  }

  const warnings = $('reportWarnings');
  warnings.replaceChildren();
  const chunkErrors = report.chunk_errors || [];
  const reviewErrors = (report.candidate_review_results || []).filter(item => item.status === 'review_error' || item.status === 'not_reviewed_no_source_rows');
  if (chunkErrors.length || reviewErrors.length) {
    warnings.hidden = false;
    const totalWarnings = chunkErrors.length + reviewErrors.length;
    const heading = document.createElement('strong');
    heading.textContent = `${totalWarnings} analysis warning(s) — review the details below`;
    const list = document.createElement('ul');
    chunkErrors.forEach(error => { const li = document.createElement('li'); li.textContent = error; list.append(li); });
    reviewErrors.forEach(item => { const li = document.createElement('li'); li.textContent = `AI review failed for ${item.attack_type || 'candidate'} (${item.ip_or_identifier || 'unknown entity'}): ${item.error || item.status}`; list.append(li); });
    warnings.append(heading, list);
  } else {
    warnings.hidden = true;
  }

  const list = $('findingsList');
  list.replaceChildren();
  if (!findings.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = chunkErrors.length
      ? 'No findings were saved. Some chunks failed, so this is not a clean security result. Resolve the warnings and run the analysis again.'
      : 'No reportable attacks were confirmed from the available evidence. Review the original logs before treating this as a clean bill of health.';
    list.append(empty);
    return;
  }

  findings.forEach(item => {
    const card = document.createElement('article');
    card.className = 'finding';
    const header = document.createElement('div');
    header.className = 'finding-head';
    const title = document.createElement('div');
    title.className = 'finding-title';
    const h3 = document.createElement('h3'); h3.textContent = item.attack_type;
    const severity = document.createElement('span'); severity.className = `severity ${item.severity}`; severity.textContent = item.severity.toUpperCase();
    const sourceTag = document.createElement('span');
    sourceTag.className = `ai-source-tag${item.ai_corroborated_by_local_model ? ' confirmed' : ''}`;
    sourceTag.textContent = item.ai_corroborated_by_local_model ? 'AI CORROBORATED' : 'SOURCE-RULED ONLY';
    title.append(h3, severity, sourceTag);
    const entity = document.createElement('span'); entity.className = 'finding-entity'; entity.textContent = item.ip_or_identifier || 'Unknown entity';
    header.append(title, entity);
    const body = document.createElement('div'); body.className = 'finding-body';
    const reason = document.createElement('p'); reason.textContent = item.reason || '';
    const evidence = document.createElement('div'); evidence.className = 'evidence';
    const label = document.createElement('div'); label.className = 'evidence-label'; label.textContent = 'SOURCE EVIDENCE'; evidence.append(label);
    (item.evidence || []).forEach(ev => {
      const row = document.createElement('div'); row.className = 'evidence-line';
      const number = document.createElement('span'); number.className = 'line-number'; number.textContent = `L${ev.line_number}`;
      const detail = document.createElement('span'); detail.textContent = ev.detail;
      row.append(number, detail); evidence.append(row);
    });
    const action = document.createElement('div'); action.className = 'action'; action.textContent = `SUGGESTED ACTION · ${item.suggested_action || 'Investigate the source and preserve logs.'}`;
    body.append(reason, evidence, action); card.append(header, body); list.append(card);
  });
}

$('exportBtn').addEventListener('click', () => {
  if (!latestJob) return;
  const payload = { job_id: latestJob.id, filename: latestJob.filename, status: latestJob.status, report: latestJob.report, findings: latestJob.findings, chunks: latestJob.chunks };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `cultive8-report-${latestJob.id.slice(0, 8)}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

updatePipeline('tokenizing', 'queued', 0);
const restoredJobId = null;
storeActiveJob(null);
if (restoredJobId) {
  activeJob = restoredJobId;
  $('progressPanel').hidden = false;
  $('analyzeBtn').disabled = true;
  $('progressTitle').textContent = 'Reconnecting to saved analysis';
  $('progressText').textContent = 'Restoring the latest job status from the local backend';
  setStatus('RECONNECTING', 'warning');
  schedulePoll(250);
}
refreshHealth();
setInterval(refreshHealth, 10000);
