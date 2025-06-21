import os
import json
import socket
import subprocess
import asyncio
import aiohttp
from datetime import datetime
from io import BytesIO

from dotenv import load_dotenv
from telegram import Update, InputFile
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# Load env variables
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN not set in environment variables!")

# File to save user recon history
HISTORY_FILE = "recon_history.json"

# Helper: Load history from file
def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return {}

# Helper: Save history to file
def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

# Add user command + domain to history
def add_to_history(user_id, command, domain):
    history = load_history()
    user_str = str(user_id)
    entry = {"command": command, "domain": domain, "time": datetime.utcnow().isoformat()}
    if user_str not in history:
        history[user_str] = []
    history[user_str].append(entry)
    save_history(history)

# Helper function to run nikto scan with tuning
async def run_nikto_scan(domain: str, output_file: str):
    # Nikto command with tuning flags 1,2,3,b (File Upload, Interesting Files, Misconfiguration, Backup files)
    cmd = [
        "nikto",
        "-h", f"http://{domain}",
        "-o", output_file,
        "-Format", "txt",
        "-Tuning", "123b"
    ]
    try:
        # Run command synchronously - can be improved with async subprocess if needed
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # 10 mins timeout
        return result.returncode == 0
    except Exception as e:
        print(f"Error running nikto scan: {e}")
        return False

# Subdomain Finder using public API (crt.sh)
async def find_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            if sub.endswith(domain):
                                subdomains.add(sub.lower())
    except Exception as e:
        print(f"Error fetching subdomains: {e}")
    return sorted(subdomains)

# Live domain status check (simple ping)
async def check_domain_status(domain):
    proc = await asyncio.create_subprocess_shell(
        f"ping -c 1 {domain}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode == 0:
        return True
    return False

# Port scanner (top 100 common ports)
COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,
    3389,5900,8080,8443,10000
]
async def scan_ports(domain):
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return []

    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            continue
    return open_ports

# WHOIS lookup using socket
def whois_lookup(domain):
    try:
        import whois
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# Subdomain takeover check (basic patterns)
async def check_takeover(subdomain):
    # Basic services known for takeover vulnerabilities
    takeover_signatures = {
        "Amazon S3": "NoSuchBucket",
    "GitHub": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "Bitbucket": "Repository not found",
    "CloudFront": "ERROR: The request could not be satisfied.",
    "Pantheon": "404 Not Found",
    "Azure": "404 Web Site not found",
    "Tumblr": "There's nothing here.",
    "Desk": "Please check your DNS settings",
    "Fastly": "Fastly error: unknown domain",
    "Cargo": "404 Not Found",
    "Helprace": "The page you were looking for doesn't exist.",
    "Pingdom": "Public report not found",
    "Tictail": "Tictail has been closed",
    "TeamWork": "Oops - We didn't find your site.",
    "WordPress": "Do you want to register",
    "Zendesk": "Help Center Closed",
    "Surge": "project not found",
    "Launchrock": "It looks like you may have taken a wrong turn",
    "Readme.io": "Project doesn't exist... yet!",
    "Simplebooklet": "We can't find that page",
    "Statuspage": "page not found",
    "Strikingly": "page could not be found",
    "Thinkific": "Oops! This page is no longer available",
    "Unbounce": "The requested URL was not found on this server",
    "Wishpond": "404 Error - Page Not Found",
    "Webflow": "The page you are looking for doesn’t exist",
    "UptimeRobot": "page not found",
    "Zoho Sites": "We couldn't find the page you're looking for.",
    "AfterShip": "Oops! The page you are looking for does not exist",
    "Acquia": "Website not found",
    "Bigcartel": "Oops! We couldn’t find that page.",
    "Campaign Monitor": "does not exist",
    "Close.io": "not found",
    "FeedPress": "The feed has not been found.",
    "Freshdesk": "Company Not Found",
    "Ghost": "The thing you were looking for is no longer here",
    "JetBrains": "is not a registered InCloud site",
    "LaunchDarkly": "not found",
    "Smartling": "Domain is not configured"
    "Intercom": r"This app does not exist",
    "Helpjuice": r"This knowledge base no longer exists",
    "Kinsta": r"No site found at this domain",
    "GetResponse": r"Page not found",
    "Kajabi": r"Sorry, this page isn't available",
    "Teachable": r"This school is no longer available",
    "Thinkific": r"This page is no longer available",
    "Instapage": r"404 - page not found",
    "NationBuilder": r"Website Not Found",
    "Vend": r"This store is unavailable",
    "Canny": r"404 - That page doesn’t exist",
    "Aha!": r"Not found - Aha!",
    "Gumroad": r"Sorry, this page no longer exists",
    "ReadTheDocs": r"404 Not Found",
    "Fly.io": r"404 Not Found",
    "Foxycart": r"This store does not exist",
    "HelpScout": r"not found",
    "Brightcove": r"The requested page could not be found",
     "Agile CRM": r"This domain is not configured",

    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{subdomain}", timeout=10) as resp:
                text = await resp.text()
                for service, signature in takeover_signatures.items():
                    if signature in text:
                        return f"Possible takeover vulnerability detected: {service}"
    except Exception:
        return "No takeover vulnerability detected or domain unreachable."
    return "No takeover vulnerability detected."

# Screenshot capture using headless chromium (using playwright or similar tool)
async def capture_screenshot(domain):
    from pyppeteer import launch
    try:
        browser = await launch(headless=True, args=['--no-sandbox'])
        page = await browser.newPage()
        await page.goto(f"http://{domain}", timeout=15000)
        screenshot = await page.screenshot()
        await browser.close()
        return screenshot
    except Exception as e:
        return None

# Generate PDF report from text (using fpdf)
def generate_pdf_report(text, filename="report.pdf"):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)
    for line in text.split("\n"):
        pdf.cell(0, 10, line, ln=True)
    pdf.output(filename)
    return filename

# Bot commands start here

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Hello! मैं आपका Red Team Bot हूँ।\n"
        "Use /help to see commands."
    )
 
 
async def nikto_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /nikto <domain>")
        return

    domain = context.args[0].lower()
    output_file = f"nikto_{domain}.txt"

    await update.message.reply_text(f"🚨 Running Nikto scan for {domain}...\nThis may take a few minutes...")

    success = await run_nikto_scan(domain, output_file)

    if success and os.path.exists(output_file):
        add_to_history(update.effective_user.id, "nikto", domain)
        with open(output_file, "rb") as f:
            await update.message.reply_document(document=f, filename=output_file)
    else:
        await update.message.reply_text("❌ Failed to complete Nikto scan.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "Available commands:\n"
        "/subdomain <domain> - Find subdomains\n"
        "/status <domain> - Check if domain is live\n"
        "/portscan <domain> - Scan common ports\n"
        "/whois <domain> - WHOIS lookup\n"
        "/screenshot <domain> - Capture website screenshot\n"
        "/takeover <subdomain> - Check subdomain takeover\n"
        "/export - Export your recon history report\n"
    )
    await update.message.reply_text(help_text)


   
async def subdomain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /subdomain <domain>")
        return
    domain = context.args[0].lower()
    await update.message.reply_text(f"🔍 Searching subdomains for {domain} ...")
    subdomains = await find_subdomains(domain)
    if not subdomains:
        await update.message.reply_text("No subdomains found.")
        return

    add_to_history(update.effective_user.id, "subdomain", domain)

    # Telegram message limit ~4096 chars, so send in chunks of 30 subdomains
    chunk_size = 30
    for i in range(0, len(subdomains), chunk_size):
        chunk = subdomains[i:i+chunk_size]
        msg = "\n".join(chunk)
        await update.message.reply_text(f"Subdomains:\n{msg}")

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /status <domain>")
        return
    domain = context.args[0].lower()
    await update.message.reply_text(f"⏳ Checking status for {domain} ...")
    status = await check_domain_status(domain)
    msg = f"{domain} is {'UP ✅' if status else 'DOWN ❌'}"
    add_to_history(update.effective_user.id, "status", domain)
    await update.message.reply_text(msg)

async def portscan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /portscan <domain>")
        return
    domain = context.args[0].lower()
    await update.message.reply_text(f"🔍 Scanning common ports on {domain} ... (this may take some time)")
    ports = await scan_ports(domain)
    add_to_history(update.effective_user.id, "portscan", domain)
    if ports:
        await update.message.reply_text(f"Open ports on {domain}:\n" + ", ".join(map(str, ports)))
    else:
        await update.message.reply_text("No open ports found or host unreachable.")

async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /whois <domain>")
        return
    domain = context.args[0].lower()
    await update.message.reply_text(f"Fetching WHOIS info for {domain} ...")
    result = whois_lookup(domain)
    add_to_history(update.effective_user.id, "whois", domain)
    await update.message.reply_text(result[:4000])  # Telegram limit

async def screenshot_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /screenshot <domain>")
        return
    domain = context.args[0].lower()
    await update.message.reply_text(f"Capturing screenshot of {domain} ... (this may take a few seconds)")
    screenshot = await capture_screenshot(domain)
    add_to_history(update.effective_user.id, "screenshot", domain)
    if screenshot:
        bio = BytesIO(screenshot)
        bio.name = f"{domain}.png"
        bio.seek(0)
        await update.message.reply_photo(photo=bio)
    else:
        await update.message.reply_text("Failed to capture screenshot.")

async def takeover_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /takeover <subdomain>")
        return
    subdomain = context.args[0].lower()
    await update.message.reply_text(f"Checking takeover possibility for {subdomain} ...")
    result = await check_takeover(subdomain)
    add_to_history(update.effective_user.id, "takeover", subdomain)
    await update.message.reply_text(result)

async def export_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    history = load_history()
    if user_id not in history or not history[user_id]:
        await update.message.reply_text("You have no recon history.")
        return

    text = f"Recon History Report for User ID: {user_id}\n\n"
    for i, entry in enumerate(history[user_id], 1):
        text += f"{i}. Command: {entry['command']}\n   Domain: {entry['domain']}\n   Time: {entry['time']}\n\n"

    pdf_filename = f"recon_report_{user_id}.pdf"
    generate_pdf_report(text, filename=pdf_filename)

    try:
        with open(pdf_filename, "rb") as f:
            await update.message.reply_document(document=f, filename=pdf_filename)
    except Exception as e:
        await update.message.reply_text(f"Error sending report: {e}")

    # Send PDF
from telegram.ext import ApplicationBuilder

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("subdomain", subdomain_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("portscan", portscan_command))
    app.add_handler(CommandHandler("whois", whois_command))
    app.add_handler(CommandHandler("nikto", nikto_command))
    app.add_handler(CommandHandler("screenshot", screenshot_command))
    app.add_handler(CommandHandler("takeover", takeover_command))
    app.add_handler(CommandHandler("export", export_command))

    print("🚀 RedTeam Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()