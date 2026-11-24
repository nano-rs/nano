// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5834: the toaster renders above every modal. A click on a toast (its
 * close button, an action, its scroll body) is not an "outside" interaction
 * that should dismiss the open Dialog or Sheet.
 */
export function keepOpenOnToastInteraction<E extends Event>(handler?: (event: E) => void): (event: E) => void {
  return (event: E) => {
    const target = event.target;
    if (target instanceof Element && target.closest('[data-sonner-toaster]')) event.preventDefault();
    handler?.(event);
  };
}
