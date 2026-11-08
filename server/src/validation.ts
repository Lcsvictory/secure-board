export function positiveId(value: unknown): number | null {
  if (typeof value === "string") {
    if (!/^\d+$/.test(value)) return null;
  } else if (typeof value !== "number") {
    return null;
  }

  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) return null;
  return id;
}
