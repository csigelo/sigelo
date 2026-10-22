// SPDX-License-Identifier: MIT
// What the page loads in place of contact/platform-node.mjs (index.html's import map): the carrier,
// the contact store, links, relays and enrolment import Node's platform as their default; in the
// page every carrier is given the browser's (platform-web.mjs), so the default is none, and a
// carrier made without a platform is refused (TypeError: platform).
export const platform = null, files = null, path = null;
/** No proxies in a page: the browser's own settings apply. */
export const proxyFor = () => null;
