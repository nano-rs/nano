// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { visibleSources, canComplete } from './source-onboarding';
import type { PlannedSource } from './api/source-onboarding';
const row = (overrides: Partial<PlannedSource> = {}): PlannedSource => ({ id:'1',name:'Firewall',vendor:'Palo Alto',expectedType:'pan_os',waveId:null,priority:2,owner:'Alice',target:null,notes:'Change 42',linkedLogSourceId:null,completed:false,completedAt:null,completedBy:null,dismissedLogSourceIds:[],suggestion:null,live:null,progress:{c1:false,c2:false,c3:false,c4:false,c5:false,issue:false,ready:false,stage:'Not connected',late:false,parsingKnown:false},rulesNeeded:0,rules:[],effectiveTarget:null,...overrides });
describe('onboarding visibility and actions', () => {
 it('hides completed rows but always shows regression', () => { const completed=row({completed:true}); const regressed=row({id:'2',completed:true,progress:{...completed.progress,issue:true}}); expect(visibleSources([completed,regressed],false,'all','')).toEqual([regressed]); expect(visibleSources([completed,regressed],true,'all','')).toHaveLength(2); });
 it('filters case-insensitively across planning fields', () => { expect(visibleSources([row()],false,'all','ALICE')).toHaveLength(1); expect(visibleSources([row()],false,'all','42')).toHaveLength(1); expect(visibleSources([row()],false,'all','unknown')).toHaveLength(0); });
 it('never unlocks completion with unknown telemetry', () => { expect(canComplete(row(),true)).toBe(false);expect(canComplete(row(),false)).toBe(true);expect(canComplete(row({completed:true}),true)).toBe(true); });
 it('filters readiness and attention independently', () => { const ready=row({progress:{...row().progress,ready:true}});expect(visibleSources([ready],false,'ready','')).toHaveLength(1);expect(visibleSources([ready],false,'attention','')).toHaveLength(0); });
});
