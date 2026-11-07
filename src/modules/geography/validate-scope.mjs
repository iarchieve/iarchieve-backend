export async function validateScope(scope, catalog) {
  if (!scope || !(await catalog.hasCountry(scope.countryId))) return false;
  if (scope.type === 'country') return scope.cityId === null;
  return scope.type === 'city' && typeof scope.cityId === 'string'
    && await catalog.hasCity(scope.countryId, scope.cityId);
}
