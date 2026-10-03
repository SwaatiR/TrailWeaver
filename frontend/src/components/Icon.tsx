import type { ReactNode, SVGProps } from "react";

export type IconName =
  | "alert"
  | "arrow"
  | "attack"
  | "cloud"
  | "database"
  | "history"
  | "identity"
  | "incident"
  | "key"
  | "network"
  | "overview"
  | "search"
  | "server"
  | "settings"
  | "shield"
  | "signal"
  | "storage";

interface IconProps extends SVGProps<SVGSVGElement> {
  name: IconName;
}

const paths: Record<IconName, ReactNode> = {
  alert: <path d="M12 3 2.8 19h18.4L12 3Zm0 5.5v4.8m0 3.2h.01" />,
  arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
  attack: <path d="M7 17 17 7M8 7h9v9M5 5l4 1M5 5l1 4M19 19l-4-1m4 1-1-4" />,
  cloud: <path d="M7 18h10a4 4 0 0 0 .7-7.94A6 6 0 0 0 6.3 8.4 4.8 4.8 0 0 0 7 18Z" />,
  database: <path d="M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3Zm0 0v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6m-16 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" />,
  history: <path d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-13v5l3.5 2" />,
  identity: <path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm7 8a7 7 0 0 0-14 0" />,
  incident: <path d="M12 3 4 6v6c0 4.4 3.1 7.7 8 9 4.9-1.3 8-4.6 8-9V6l-8-3Zm0 5v5m0 3h.01" />,
  key: <path d="M14 10a4 4 0 1 0-3.4 3.76L12 15h2v2h2v2h3v-3l-5-6Z" />,
  network: <path d="M12 12h.01M5 5h.01M19 5h.01M5 19h.01M19 19h.01M12 12 5.5 5.5m6.5 6.5 7-7M12 12l-6.5 6.5M12 12l7 7" />,
  overview: <path d="M4 13h6V4H4v9Zm10 7h6V4h-6v16ZM4 20h6v-3H4v3Z" />,
  search: <path d="m20 20-4.5-4.5m2.5-5A7.5 7.5 0 1 1 3 10.5a7.5 7.5 0 0 1 15 0Z" />,
  server: <path d="M4 5h16v6H4V5Zm0 8h16v6H4v-6Zm3-5h.01M7 16h.01" />,
  settings: <path d="M12 15.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4Zm7-3.2 2-1-2-3.5-2.2.4a7 7 0 0 0-1.6-.9L14.5 5h-5l-.7 2a7 7 0 0 0-1.6.9L5 7.5 3 11l2 1a7 7 0 0 0 0 2l-2 1 2 3.5 2.2-.4a7 7 0 0 0 1.6.9l.7 2h5l.7-2a7 7 0 0 0 1.6-.9l2.2.4 2-3.5-2-1a7 7 0 0 0 0-2Z" />,
  shield: <path d="M12 3 4 6v6c0 4.4 3.1 7.7 8 9 4.9-1.3 8-4.6 8-9V6l-8-3Zm-3 9 2 2 4-5" />,
  signal: <path d="M4 19V9m5 10V5m6 14v-7m5 7V3" />,
  storage: <path d="M4 5h16v14H4V5Zm0 4h16M8 15h.01" />,
};

export function Icon({ name, ...props }: IconProps) {
  return (
    <svg
      aria-hidden="true"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      {paths[name]}
    </svg>
  );
}
