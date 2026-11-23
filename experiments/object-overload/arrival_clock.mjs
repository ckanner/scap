/** Absolute arrival deadlines with one unconditional event-loop turn per offer.
 * The turn never observes capacity or waits for an SDK call to finish. It gives
 * ready I/O a chance to run even when every planned target is already overdue.
 */
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises';

const systemClock = { now: () => process.hrtime.bigint(), delay, turn: nextTurn };

export async function until(target, clock = systemClock) {
  while (clock.now() < target)
    await clock.delay(Math.max(1, Number(target - clock.now()) / 1e6));
  await clock.turn();
}
