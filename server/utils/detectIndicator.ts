import type {
  IndicatorType,
} from "../types/intelligence"

export function detectIndicatorType(
  value: string,
): IndicatorType {
  const indicator = value.trim()

  if (
    /^CVE-\d{4}-\d{4,}$/i.test(indicator)
  ) {
    return "cve"
  }

  if (
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(
      indicator,
    )
  ) {
    const octets = indicator
      .split(".")
      .map(Number)

    if (
      octets.every(
        (octet) =>
          octet >= 0 &&
          octet <= 255,
      )
    ) {
      return "ip"
    }
  }

  if (
    /^https?:\/\/\S+$/i.test(indicator)
  ) {
    return "url"
  }

  if (
    /^[a-fA-F0-9]{32}$/.test(indicator) ||
    /^[a-fA-F0-9]{40}$/.test(indicator) ||
    /^[a-fA-F0-9]{64}$/.test(indicator)
  ) {
    return "hash"
  }

  if (
    /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(
      indicator,
    )
  ) {
    return "domain"
  }

  return "unknown"
}