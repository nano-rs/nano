// SPDX-License-Identifier: AGPL-3.0-or-later

import { Palette } from 'lucide-react';
import { useTheme } from 'next-themes';

import {
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from '@/components/ui/dropdown-menu';
import { ThemeDot } from '@/components/ui/theme-swatches';
import { THEMES, THEME_LABELS } from '@/lib/theme';

/**
 * User-menu theme submenu: one menu-native radio item per theme, with the
 * theme's swatch inside the item. Radix roving focus reaches radio items, so
 * every theme is selectable by keyboard (a row of buttons nested inside a
 * menu item is not). Selecting keeps the menu open so themes can be compared.
 */
export function ThemeMenu({ itemCls }: { itemCls?: string }) {
  const { theme, setTheme } = useTheme();
  return (
    <DropdownMenuSub>
      <DropdownMenuSubTrigger className={itemCls}>
        <Palette className="w-3.5 h-3.5" />
        Theme
      </DropdownMenuSubTrigger>
      <DropdownMenuSubContent className="w-44">
        <DropdownMenuRadioGroup value={theme ?? ''} onValueChange={setTheme}>
          {THEMES.map((name) => (
            <DropdownMenuRadioItem
              key={name}
              value={name}
              onSelect={(event) => event.preventDefault()}
              className="gap-2 py-1 text-[11.5px]"
            >
              <ThemeDot theme={name} />
              {THEME_LABELS[name]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuSubContent>
    </DropdownMenuSub>
  );
}
