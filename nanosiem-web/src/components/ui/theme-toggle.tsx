// SPDX-License-Identifier: AGPL-3.0-or-later

import { Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { THEMES, THEME_LABELS } from "@/lib/theme"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export function ThemeToggle() {
  const { setTheme, theme } = useTheme()
  const [mounted, setMounted] = useState(false)

  // Avoid hydration mismatch by only rendering after mount
  useEffect(() => {
    setMounted(true)
  }, [])

  const handleThemeChange = (newTheme: string) => {
    console.log('Setting theme to:', newTheme)
    setTheme(newTheme)
    // Force update the class on html element as a fallback. Clear EVERY theme
    // class, not a hardcoded light/dark pair — a leftover `matte` alongside a
    // newly added `light` leaves both token blocks live, and the later one in
    // the stylesheet wins regardless of what was picked.
    const root = document.documentElement
    root.classList.remove(...THEMES)
    if (newTheme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
      root.classList.add(systemTheme)
    } else {
      root.classList.add(newTheme)
    }
  }

  if (!mounted) {
    // Return a placeholder with same dimensions to avoid layout shift
    return (
      <Button variant="ghost" size="icon" disabled>
        <Sun className="h-4 w-4" />
        <span className="sr-only">Toggle theme</span>
      </Button>
    )
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
          <Sun className="h-4 w-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute h-4 w-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {THEMES.map((name) => (
          <DropdownMenuItem
            key={name}
            onClick={() => handleThemeChange(name)}
            className={theme === name ? "bg-accent" : ""}
          >
            {THEME_LABELS[name]}
          </DropdownMenuItem>
        ))}
        <DropdownMenuItem onClick={() => handleThemeChange("system")} className={theme === "system" ? "bg-accent" : ""}>
          System
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
