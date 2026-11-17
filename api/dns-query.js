// Vercel Edge adapter
import { handle } from "../src/core.js";

export const config = { runtime: "edge", regions: ["hkg1"] };

export default function handler(request) {
  const ip = request.headers.get("x-real-ip") || (request.headers.get("x-forwarded-for") || "").split(",")[0].trim();
  return handle(request, { env: process.env, ip });
}
