// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Enrichment Detail Page
 *
 * Displays the configuration UI for a specific enrichment source.
 * Dynamically loads the appropriate provider component based on source_type.
 */

import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Loader2, ArrowLeft } from 'lucide-react';
import { api, EnrichmentSource } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

// NAN-1111: ThreatFox + Tor moved to the marketplace; their provider
// components were deleted from this directory. IPinfo Lite stays
// native — see project_ipinfo_lite_stays_native memory for the
// volume + schema rationale. The /enrichments/{threatfox,tor_exit_nodes}
// deep-links are redirected to /marketplace?slug=... in App.tsx
// (LegacyEnrichmentRoute) before this page ever renders, so the
// dispatch table only needs to cover the still-native sources.
import { IPinfoLiteProvider } from '@/components/enrichment/providers';

type ProviderComponentType = React.ComponentType<{
  source: EnrichmentSource;
  onRefresh: () => void;
}>;

// Provider component mapping by source type (still-native sources only).
const PROVIDER_BY_TYPE: Record<string, ProviderComponentType> = {
  'ipinfo_lite': IPinfoLiteProvider,
};

// Helper to get the right provider component
function getProviderComponent(source: EnrichmentSource): ProviderComponentType | undefined {
  return PROVIDER_BY_TYPE[source.source_type];
}

export function EnrichmentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [source, setSource] = useState<EnrichmentSource | null>(null);
  const [loading, setLoading] = useState(true);

  useDocumentTitle(source?.name || 'Enrichment', [source?.id]);
  useBreadcrumbTitle(source?.name);

  const fetchSource = async () => {
    try {
      setLoading(true);
      const sources = await api.listEnrichmentSources();
      const found = sources.find(s => s.id === id);
      setSource(found || null);
    } catch {
      toast({
        title: 'Error',
        description: 'Failed to load enrichment source',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSource();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!source) {
    return (
      <div className="p-8">
        <Card className="bg-red-500/10 border-red-500/20 rounded-2xl">
          <CardContent className="p-6">
            <p className="text-red-400">Enrichment source not found</p>
            <Link to="/enrichments">
              <Button className="mt-4">Back to Enrichments</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Get the provider component for this source
  const ProviderComponent = getProviderComponent(source);

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button onClick={() => navigate(-1)} className="p-2 hover:bg-accent/50 rounded-lg transition-colors">
          <ArrowLeft className="w-5 h-5 text-muted-foreground" />
        </button>
        <div>
          <h1 className="text-3xl font-bold text-foreground">{source.name}</h1>
          <p className="text-muted-foreground mt-1">{source.description}</p>
        </div>
      </div>

      {/* Render provider-specific UI or fallback */}
      {ProviderComponent ? (
        <ProviderComponent source={source} onRefresh={fetchSource} />
      ) : (
        <Card className="bg-card border-0 rounded-2xl">
          <CardContent className="p-6">
            <p className="text-muted-foreground">
              Configuration for this enrichment source type ({source.source_type}) is not yet available.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
