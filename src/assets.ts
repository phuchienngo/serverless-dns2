/** @fileoverview Reading the project's static assets (built by build-lists). */

import type {Env} from './types.js';

/**
 * @param path Where the asset is served, such as `/rules.json`.
 * @return The response of the asset.
 * @throws If there is no ASSETS binding, or the asset cannot be had.
 */
export async function fetchAsset(
  env: Env,
  host: string,
  path: string
): Promise<Response> {
  if (!env.ASSETS) {
    throw new Error('no assets');
  }
  const response = await env.ASSETS.fetch(`https://${host}${path}`);
  if (!response.ok) {
    throw new Error(`${path}: HTTP ${response.status}`);
  }
  return response;
}
