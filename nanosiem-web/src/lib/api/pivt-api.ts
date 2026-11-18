// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5571: the REST client as pivt page actions use it. Same session, same
// permissions, same handlers as the analyst's own clicks; requests are marked
// `X-Nano-Origin: pivt` so the audit log reads "via pivt" (request-origin.ts).
import { api } from './index';
import { withRequestOrigin } from './request-origin';

export const pivtApi = withRequestOrigin('pivt', api);
