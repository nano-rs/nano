import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';
const mocks = {
  '@/hooks/use-api': `export const useDashboards = () => ({data: new URLSearchParams(location.search).has('populated') ? [{id:'board-1', name:'SOC Overview', description:'Security activity across your stack.', panel_count:4, visibility:'private', owner_name:'Alex Analyst', updated_at:'2026-10-17T12:00:00Z'}] : [], loading:false, refetch:()=>{}}); export const useCreateDashboard = () => ({mutate:async()=>({id:'created'}),loading:false}); export const useDeleteDashboard=useCreateDashboard; export const useImportDashboard=useCreateDashboard;`,
  '@/contexts/AuthContext': `export const useAuth=()=>({hasPermission:()=>true});`,
  '@/hooks/use-capabilities': `export const useCapabilities=()=>({capabilities:{melod:true}});`,
  '@/hooks/use-toast': `export const useToast=()=>({toast:()=>{}});`,
  '@/enterprise/components/dashboard/DashboardGenerationWizard': `export const DashboardGenerationWizard=()=>null;`,
};
export default defineConfig({
  plugins: [
    {
      name: 'fixtures',
      enforce: 'pre',
      resolveId(id) {
        const key = Object.keys(mocks).find(
          (key) =>
            id === key ||
            id.endsWith(key.slice(1)) ||
            id.endsWith(key.slice(1) + '.tsx') ||
            id.endsWith(key.slice(1) + '.ts'),
        );
        if (key) return '\0fixture:' + key;
      },
      load(id) {
        if (id.startsWith('\0fixture:')) return mocks[id.slice(9)];
      },
    },
    react(),
    tailwindcss(),
  ],
  resolve: { alias: { '@': path.resolve('src') } },
  server: { host: '127.0.0.1', port: 1482, strictPort: true },
});
