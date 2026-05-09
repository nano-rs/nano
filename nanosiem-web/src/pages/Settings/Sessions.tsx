// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sessions Management Page
 * 
 * Requirements: 11.5
 * - List active sessions
 * - Terminate session action
 * - Highlight current session
 */

import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Loader2,
  Monitor,
  Search,
  LogOut,
  Globe,
  Clock,
  Smartphone,
  Laptop,
  Star,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api, SessionInfo } from '@/lib/api';
import { formatUTC, formatRelativeUTC } from '@/lib/date-utils';

// Parse user agent to get device info
function parseUserAgent(userAgent?: string): { device: string; browser: string; icon: React.ReactNode } {
  if (!userAgent) {
    return { device: 'Unknown', browser: 'Unknown', icon: <Monitor className="w-4 h-4" /> };
  }

  const ua = userAgent.toLowerCase();
  let device = 'Desktop';
  let browser = 'Unknown';
  let icon: React.ReactNode = <Laptop className="w-4 h-4" />;

  // Detect device
  if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
    device = 'Mobile';
    icon = <Smartphone className="w-4 h-4" />;
  } else if (ua.includes('tablet') || ua.includes('ipad')) {
    device = 'Tablet';
    icon = <Smartphone className="w-4 h-4" />;
  }

  // Detect browser
  if (ua.includes('chrome') && !ua.includes('edg')) {
    browser = 'Chrome';
  } else if (ua.includes('firefox')) {
    browser = 'Firefox';
  } else if (ua.includes('safari') && !ua.includes('chrome')) {
    browser = 'Safari';
  } else if (ua.includes('edg')) {
    browser = 'Edge';
  } else if (ua.includes('opera') || ua.includes('opr')) {
    browser = 'Opera';
  }

  return { device, browser, icon };
}

// Content component for use in tabbed Access Control page
export function SessionsContent() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();

  // Data state
  const [mySessions, setMySessions] = useState<SessionInfo[]>([]);
  const [allSessions, setAllSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const activeTab = searchParams.get('sessionsTab') || 'my-sessions';
  const setActiveTab = (tab: string) => {
    const params = new URLSearchParams(searchParams);
    params.set('sessionsTab', tab);
    setSearchParams(params);
  };
  
  // Dialog state
  const [terminateDialogOpen, setTerminateDialogOpen] = useState(false);
  const [selectedSession, setSelectedSession] = useState<SessionInfo | null>(null);
  const [terminateLoading, setTerminateLoading] = useState(false);

  const canViewAllSessions = hasPermission('users:view');

  // Fetch sessions
  const fetchData = async () => {
    setLoading(true);
    try {
      const mySessionsRes = await api.listMySessions();
      setMySessions(mySessionsRes.sessions);

      if (canViewAllSessions) {
        const allSessionsRes = await api.listAllSessions();
        setAllSessions(allSessionsRes.sessions);
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load sessions',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [canViewAllSessions]);

  // Filter sessions by search query
  const filterSessions = (sessions: SessionInfo[]) => {
    if (!searchQuery) return sessions;
    const query = searchQuery.toLowerCase();
    return sessions.filter(session =>
      session.ip_address?.toLowerCase().includes(query) ||
      session.user_agent?.toLowerCase().includes(query)
    );
  };

  // Open terminate dialog
  const handleOpenTerminate = (session: SessionInfo) => {
    setSelectedSession(session);
    setTerminateDialogOpen(true);
  };

  // Terminate session
  const handleTerminate = async () => {
    if (!selectedSession) return;

    setTerminateLoading(true);
    try {
      await api.terminateSession(selectedSession.id);
      toast({ 
        title: 'Session terminated', 
        description: selectedSession.is_current 
          ? 'You will be logged out shortly.' 
          : 'The session has been terminated.' 
      });
      setTerminateDialogOpen(false);
      setSelectedSession(null);
      
      // If terminating current session, the user will be logged out
      if (!selectedSession.is_current) {
        fetchData();
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to terminate session',
        variant: 'destructive',
      });
    } finally {
      setTerminateLoading(false);
    }
  };


  // Render session table
  const renderSessionTable = (sessions: SessionInfo[]) => {
    const filteredSessions = filterSessions(sessions);

    return (
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead>Device</TableHead>
            <TableHead>IP Address</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>Last Active</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead className="w-[100px]"></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filteredSessions.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                No sessions found
              </TableCell>
            </TableRow>
          ) : (
            filteredSessions.map((session) => {
              const { device, browser, icon } = parseUserAgent(session.user_agent);
              
              return (
                <TableRow 
                  key={session.id} 
                  className={session.is_current ? 'bg-primary/5' : ''}
                >
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-accent/50 rounded-lg text-muted-foreground">
                        {icon}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-foreground font-medium">{browser}</span>
                          {session.is_current && (
                            <Badge className="bg-primary/10 text-primary rounded-lg text-xs">
                              <Star className="w-3 h-3 mr-1" />
                              Current
                            </Badge>
                          )}
                        </div>
                        <span className="text-xs text-muted-foreground">{device}</span>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 text-foreground">
                      <Globe className="w-3 h-3 text-muted-foreground" />
                      {session.ip_address || 'Unknown'}
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    <div className="flex items-center gap-2">
                      <Clock className="w-3 h-3 text-muted-foreground" />
                      {formatUTC(session.created_at)}
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {formatRelativeUTC(session.last_used_at)}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {formatUTC(session.expires_at)}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleOpenTerminate(session)}
                      className={`text-destructive hover:text-destructive ${session.is_current ? 'opacity-75' : ''}`}
                    >
                      <LogOut className="w-4 h-4 mr-1" />
                      {session.is_current ? 'Logout' : 'Terminate'}
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })
          )}
        </TableBody>
      </Table>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <p className="text-muted-foreground">View and manage active login sessions</p>

      {/* Sessions */}
      <Card className="border-0">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="relative max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search by IP or device..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {canViewAllSessions ? (
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList>
                <TabsTrigger value="my-sessions" >
                  My Sessions ({mySessions.length})
                </TabsTrigger>
                <TabsTrigger value="all-sessions" >
                  All Sessions ({allSessions.length})
                </TabsTrigger>
              </TabsList>
              <TabsContent value="my-sessions">
                {renderSessionTable(mySessions)}
              </TabsContent>
              <TabsContent value="all-sessions">
                {renderSessionTable(allSessions)}
              </TabsContent>
            </Tabs>
          ) : (
            renderSessionTable(mySessions)
          )}
        </CardContent>
      </Card>

      {/* Terminate Confirmation Dialog */}
      <AlertDialog open={terminateDialogOpen} onOpenChange={setTerminateDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {selectedSession?.is_current ? 'Logout' : 'Terminate Session'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {selectedSession?.is_current ? (
                'Are you sure you want to logout? You will need to sign in again.'
              ) : (
                <>
                  Are you sure you want to terminate this session?
                  <div className="mt-2 p-2 bg-muted/50 rounded-lg text-sm">
                    <div><span className="text-muted-foreground">IP:</span> {selectedSession?.ip_address || 'Unknown'}</div>
                    <div><span className="text-muted-foreground">Created:</span> {selectedSession && formatUTC(selectedSession.created_at)}</div>
                  </div>
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleTerminate}
              disabled={terminateLoading}
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
            >
              {terminateLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              {selectedSession?.is_current ? 'Logout' : 'Terminate'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}


// Standalone page wrapper for backward compatibility
export function SessionsPage() {
  return (
    <div className="p-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-primary/10 rounded-xl">
          <Monitor className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl font-bold text-foreground">Active Sessions</h1>
      </div>
      <SessionsContent />
    </div>
  );
}
