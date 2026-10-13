import { resolveLocale } from "@/i18n/config";

import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// Static page metadata follows the selected build language.
const META_BY_LOCALE = {
  en: {
    title: "AegisLoop: Security operations",
    description: "ARTEX-based vulnerability assessment, incident investigation, and attack and defense improvement console",
  },
  ko: {
    title: "AegisLoop: 공격·방어 보안 운영",
    description: "ARTEX 기반 취약점 진단·침해 조사·공격 방어 개선 콘솔",
  },
  zh: {
    title: "AegisLoop — 攻防安全运营",
    description: "基于 ARTEX 的漏洞诊断、事件调查与攻防改进控制台",
  },
} as const;

export const APP_CONFIG = {
  name: "AegisLoop",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX.`,
  meta: META_BY_LOCALE[resolveLocale()],
};
