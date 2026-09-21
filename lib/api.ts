import { apiBaseUrl } from "@/lib/config";
import type { ApiResult } from "@/types/api";

export async function apiGet<T>(path: string): Promise<ApiResult<T>> {
  const url = `${apiBaseUrl}${path.startsWith("/") ? path : `/${path}`}`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`);
  }

  const data = (await response.json()) as T;
  return { data, status: response.status };
}
