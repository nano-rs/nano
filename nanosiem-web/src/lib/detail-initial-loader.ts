/**
 * NAN-5329: whether a detail page should replace its whole tree with a
 * loading spinner. Only on the FIRST load of a record (or a switch to a
 * different record). A background refetch (after Validate / Save VRL) keeps the
 * page mounted, so local state such as the parser test lab's pasted samples
 * and results survives it.
 */
export function showInitialLoader(
  loading: boolean,
  data: { id: string } | null | undefined,
  routeId: string | undefined,
): boolean {
  if (!loading) return false;
  return !data || data.id !== routeId;
}
