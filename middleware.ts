import { createServerClient, type CookieOptions } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

// ── APPROVED BOTS (Allowed to crawl/fetch) ───────────────────────────────────
const ALLOWED_BOTS = [
  // Search Engines (SEO)
  "googlebot",
  "googlebot-image",
  "googlebot-video",
  "googlebot-news",
  "adsbot-google",
  "bingbot",
  "msnbot",
  "duckduckbot",
  "baiduspider",
  "yandexbot",
  "yandexmobilebot",
  "sogou",
  "yahoo",
  "yeti", // Naver
  
  // Answer Engines / AI Search (AEO)
  "gptbot",
  "oai-searchbot",
  "chatgpt-user",
  "perplexitybot",
  "claudebot",
  "claude-web",
  "applebot",
  "applebot-extended",
  
  // Social Previews / Share Card Crawlers (Link previews)
  "facebookexternalhit",
  "meta-externalagent",
  "twitterbot",
  "linkedinbot",
  "slackbot",
  "slack-imgproxy",
  "discordbot",
  "whatsapp",
  "telegrambot",
  "pinterest",
  "skypeshell",
  
  // System / Developer Audit & Monitoring Tools
  "uptimerobot",
  "pingdom",
  "betterstack",
  "statuscake",
  "vercel",
  "lighthouse", // Google PageSpeed / Lighthouse
  "gtmetrix",
]

// ── BLOCKED BOT KEYWORDS (Blocked immediately) ──────────────────────────────
const BLOCKED_KEYWORDS = [
  // SEO Scrapers / Competitor Spying Tools (High frequency, zero search value)
  "ahrefsbot",
  "semrushbot",
  "dotbot",
  "rogerbot",
  "mj12bot",
  "megaindex",
  "criteobot",
  "petalbot",
  "spyfu",
  "serpstat",
  "cognitiveseo",
  "linkdex",
  "seokicks",
  "grapeshot",
  "coccoc",
  "mail.ru_bot",
  "screaming frog",
  "searchmetrics",
  "sitecheck",
  "backlink",
  "keycss",
  
  // AI Training scrapers that do NOT drive search/AEO traffic
  "ccbot", // Common Crawl
  "bytespider", // ByteDance/TikTok crawler
  "amazonbot",
  "diffbot",
  "cohere-ai",
  "anthropic-ai",
  
  // Scraping script clients / developer tools / libraries
  "curl",
  "wget",
  "urllib",
  "node-fetch",
  "axios",
  "scrapy",
  "headlesschrome",
  "selenium",
  "puppeteer",
  "playwright",
  "postman",
  "go-http-client",
  "java",
  "perl",
  "blexbot",
  "barkrowler",
  "zoominfobot",
  "exabot",
  "python",
  "libwww-perl",
  "lwp-trivial",
  "mechanize",
  "nmap",
  "httpclient",
  "http-client",
]

// ── GENERIC CRAWLER TERMS (Blocked if not in approved list) ─────────────────
const GENERIC_CRAWLER_KEYWORDS = [
  "bot",
  "spider",
  "crawler",
  "crawling",
  "scraper",
  "scraping",
]

export async function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname
  const userAgent = request.headers.get("user-agent") || ""
  const uaLower = userAgent.toLowerCase().trim()

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 1: BOT BLOCKING (Runs on ALL matched routes, including API routes)
  // ─────────────────────────────────────────────────────────────────────────

  // 1. Block missing or empty user-agents (often basic scripts/scrapers)
  if (!uaLower || uaLower.length < 12) {
    return new NextResponse(
      JSON.stringify({ error: "Access denied. Valid browser or client agent required." }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    )
  }

  // 2. Allow if it's one of the beneficial/approved bots
  const isAllowedBot = ALLOWED_BOTS.some((bot) => uaLower.includes(bot))
  if (!isAllowedBot) {
    // 3. Block if it matches explicitly disallowed bot/scraper keywords
    const isBlockedBot = BLOCKED_KEYWORDS.some((kw) => uaLower.includes(kw))
    if (isBlockedBot) {
      return new NextResponse(
        JSON.stringify({ error: "Access denied. Automated traffic from this agent is not allowed." }),
        {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }
      )
    }

    // 4. Block generic unnamed bots/spiders/scrapers that aren't on the approved list
    const isGenericBot = GENERIC_CRAWLER_KEYWORDS.some((kw) => uaLower.includes(kw))
    if (isGenericBot) {
      return new NextResponse(
        JSON.stringify({ error: "Access denied. Automated web crawling is restricted." }),
        {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }
      )
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 2: PROXY / SUPABASE / DOMAIN HEADERS (Only run on non-API routes)
  // ─────────────────────────────────────────────────────────────────────────

  // Skip proxy logic for API routes (except if it is an admin API route, but as per
  // original proxy.ts config, /api was excluded completely).
  if (pathname.startsWith('/api')) {
    return NextResponse.next()
  }

  let response = NextResponse.next()

  // Set domain context
  response.headers.set('x-upforge-domain', 'org')
  response.headers.set('x-upforge-pathname', pathname)

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get(name: string) { return request.cookies.get(name)?.value },
        set(name: string, value: string, options: CookieOptions) {
          response.cookies.set({ name, value, ...options })
        },
        remove(name: string, options: CookieOptions) {
          response.cookies.set({ name, value: '', ...options })
        },
      },
    }
  )

  // Admin route protection
  if (pathname.startsWith('/admin')) {
    if (pathname === '/admin/login' || pathname.startsWith('/api/admin/')) {
      return response 
    }

    const adminAuth = request.cookies.get('admin_auth')?.value
    if (!adminAuth || adminAuth !== 'authenticated') {
      return NextResponse.redirect(new URL('/admin/login', request.url))
    }
    // Only run expensive auth check on admin routes
    await supabase.auth.getUser()
  }

  return response
}

// Next.js middleware configuration matcher
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, robots.txt, sitemap.xml, ads.txt, llms.txt, llms-full.txt
     * - standard static file formats (png, jpg, jpeg, gif, webp, svg, css, js, woff2, json, xml)
     */
    "/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml|ads.txt|llms.txt|llms-full.txt|.*\\.(?:png|jpg|jpeg|gif|webp|svg|css|js|woff2?|json|xml)).*)",
  ],
}
