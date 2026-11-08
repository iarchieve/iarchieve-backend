const questions = ['who', 'what', 'when', 'where', 'why', 'how'];
const relationTypes = ['precedes', 'responds_to', 'causes', 'affects'];

function requireText(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError(`${label} is required`);
  }
  return value.trim();
}

// Inputs are collected original documents and proposed findings from the investigation.
export function buildReportDraft({ question, documents, events, relations = [] }) {
  const sources = new Map();
  for (const { id, url, text } of documents) {
    requireText(id, 'Source ID');
    requireText(text, 'Original document text');
    const address = new URL(url);
    if (!['https:', 'http:'].includes(address.protocol) ||
        address.username || address.password || sources.has(id)) {
      throw new TypeError('Invalid or duplicate source');
    }
    sources.set(id, { url: address.href, text });
  }

  function resolveEvidence(evidence) {
    if (!Array.isArray(evidence) || !evidence.length) {
      throw new TypeError('Each finding requires original evidence');
    }
    return evidence.map(({ sourceId, start, end }) => {
      const source = sources.get(sourceId);
      if (!source || !Number.isInteger(start) || !Number.isInteger(end) ||
          start < 0 || end <= start || end > source.text.length ||
          !source.text.slice(start, end).trim()) {
        throw new TypeError('Invalid original evidence range');
      }
      return { sourceId, url: source.url, start, end };
    });
  }

  const eventIds = new Set();
  const timeline = events.map(({ id, findings }) => {
    requireText(id, 'Event ID');
    if (eventIds.has(id)) throw new TypeError('Duplicate event ID');
    eventIds.add(id);
    const fields = Object.fromEntries(questions.map((key) => {
      const finding = findings[key];
      return [key, finding == null ? null : {
        statement: requireText(finding.statement, key),
        evidence: resolveEvidence(finding.evidence),
      }];
    }));
    if (!fields.what) throw new TypeError('Each event requires a supported description');
    const date = fields.when?.statement;
    if (date && (!/^\d{4}-\d{2}-\d{2}$/.test(date) ||
        !Number.isFinite(Date.parse(date)) ||
        new Date(date).toISOString().slice(0, 10) !== date)) {
      throw new TypeError('Event date must be YYYY-MM-DD or unknown');
    }
    return { id, fields };
  }).sort((a, b) => {
    const left = a.fields.when?.statement ?? '9999-99-99';
    const right = b.fields.when?.statement ?? '9999-99-99';
    return left.localeCompare(right);
  });

  if (!timeline.length) throw new TypeError('No supported events');
  const links = relations.map(({ from, to, type, statement, evidence }) => {
    if (!eventIds.has(from) || !eventIds.has(to) || from === to ||
        !relationTypes.includes(type)) {
      throw new TypeError('Invalid event relation');
    }
    return {
      from, to, type,
      statement: requireText(statement, 'Relation statement'),
      evidence: resolveEvidence(evidence),
    };
  });

  return {
    status: 'needs_review',
    question: requireText(question, 'Question'),
    timeline,
    relations: links,
  };
}
