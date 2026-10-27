// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 / NAN-4546 — route entries for the Automation workspace. Each page
 * mounts behind SoarRouteGate, so while SOAR is disabled (or still loading)
 * the only SOAR request is the shared settings read. Inside the gate every
 * page sits in the AutomationFrame (approvals drawer + footer counts).
 */
import { useNavigate, useParams } from 'react-router-dom';
import { SoarRouteGate } from './soar-gate';
import { RunsPage } from './RunsPage';
import { FlowViewPage, FlowsPage } from './FlowsPage';
import { CapabilitiesPage } from './CapabilitiesPage';
import { AutomationFrame } from './AutomationFrame';

export function AutomationRunsRoute() {
  return <SoarRouteGate><AutomationFrame><RunsPage /></AutomationFrame></SoarRouteGate>;
}
export function AutomationFlowsRoute() {
  return <SoarRouteGate><AutomationFrame><FlowsPage /></AutomationFrame></SoarRouteGate>;
}
export function AutomationFlowRoute() {
  return <SoarRouteGate><AutomationFrame><FlowViewPage /></AutomationFrame></SoarRouteGate>;
}
/** Approvals are a drawer over Runs (mock: approvals → drawer); this route opens it. */
export function AutomationApprovalsRoute() {
  const { id } = useParams<{ id?: string }>();
  const navigate = useNavigate();
  return (
    <SoarRouteGate>
      <AutomationFrame drawer={{ id: id ?? null, onClose: () => navigate('/automation/runs') }}>
        <RunsPage selectedId={null} />
      </AutomationFrame>
    </SoarRouteGate>
  );
}
export function AutomationCapabilitiesRoute() {
  return <SoarRouteGate><AutomationFrame><CapabilitiesPage /></AutomationFrame></SoarRouteGate>;
}
