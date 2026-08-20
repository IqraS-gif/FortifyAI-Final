// Central API Configuration for FortifyAI Frontend
// Supports Vercel deployment with dynamic Render backend URL or relative proxy rewrites
export const API_BASE = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
