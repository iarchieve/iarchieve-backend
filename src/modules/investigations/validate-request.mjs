import { validateScope } from '../geography/validate-scope.mjs';

export async function validateInvestigationRequest(input, catalog) {
  if (typeof input?.question !== 'string' || !input.question.trim()) return false;
  return validateScope(input.scope, catalog);
}
