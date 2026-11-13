/**
 * NAN-5328: the Event Stream header warns when the results table returned
 * fewer rows than the stream counted (a truncated raw-event fetch). An
 * aggregate pipeline (`stats`, `timechart`, `top`, …) always returns fewer
 * rows than the events it reads, so the warning is noise there.
 */
export function shouldWarnRowShortfall(opts: {
  eventCount: number;
  resultCount?: number;
  isAggregate?: boolean;
}): boolean {
  const { eventCount, resultCount, isAggregate } = opts;
  if (isAggregate) return false;
  if (resultCount === undefined) return false;
  return eventCount > 0 && resultCount < eventCount;
}
