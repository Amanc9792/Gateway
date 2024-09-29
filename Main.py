import aiohttp
import whois
from Wappalyzer import Wappalyzer, WebPage
import ssl
import socket
import OpenSSL
from aiogram import Bot, Dispatcher
from aiogram.types import Message
from aiogram.filters import Command
from aiogram import Router
import time
import logging
import dns.resolver
import asyncio

# Setup logging
logging.basicConfig(level=logging.INFO)

# Initialize the bot with your token
API_TOKEN = '7270384815:AAFLXWmw-t1fplduJ7hRR44zWsAGu4FDWEU'

bot = Bot(token=API_TOKEN)
router = Router()  # Router to manage handlers
dp = Dispatcher()

# Function to check SSL Certificate details asynchronously
async def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(5.0)  # Set a timeout for the SSL connection
        conn.connect((domain, 443))
        cert_bin = conn.getpeercert(True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
        cert_info = {
            "issuer": x509.get_issuer().CN,
            "subject": x509.get_subject().CN,
            "serial_number": x509.get_serial_number(),
            "valid_from": x509.get_notBefore().decode('utf-8'),
            "valid_to": x509.get_notAfter().decode('utf-8')
        }
        return cert_info
    except Exception as e:
        logging.error(f"Error fetching SSL info for {domain}: {e}")
        return f"Error fetching SSL info: {e}"

# Asynchronous function to fetch website information and verify details
async def fetch_site_info(url):
    site_info = {
        "site": url,
        "auth_gate": False,
        "captcha": False,
        "cloudflare": False,
        "http_status_code": None,
        "payment_methods": [],
        "platform": None,
        "server_info": None,
        "dns_info": None,
        "vbv": False,
        "ssl_info": None,
        "time_taken": None
    }

    try:
        start_time = time.time()

        # Use aiohttp for asynchronous HTTP requests
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                site_info["http_status_code"] = f'{response.status} {response.reason}'

                # Read response content
                html_content = await response.text()

                # Check for CAPTCHA by analyzing common CAPTCHA indicators
                captcha_keywords = ['recaptcha', 'grecaptcha', 'hcaptcha', 'captcha', 'verifyRecaptchaToken']
                site_info["captcha"] = any(keyword in html_content.lower() for keyword in captcha_keywords)

                # Check for Cloudflare protection by analyzing headers
                cloudflare_headers = ['cf-ray', 'cf-cache-status', 'Server']
                site_info["cloudflare"] = any(header in response.headers and 'cloudflare' in response.headers.get(header, '').lower() for header in cloudflare_headers)

                # Expanded check for Payment Methods by scanning HTML content
                payment_keywords = [
                    'paypal', 'stripe', 'braintree', 'square', 'cybersource', 
                    'authorize.net', '2checkout', 'adyen', 'worldpay', 'segapay', 
                    'checkout.com', 'shopify', 'razorpay', 'bolt', 'paytm', 
                    'venmo', 'googlepay', 'revolut', 'eway', 'woocommerce', 'upi', 
                    'applepay', 'payflow', 'payeezy', 'paddle', 'payoneer', 'recurly', 
                    'klarna', 'paysafe', 'webmoney', 'payeer', 'payu', 'skrill'
                ]
                payment_methods_detected = [method for method in payment_keywords if method in html_content.lower()]
                site_info["payment_methods"] = payment_methods_detected if payment_methods_detected else ["None"]

                # Detect Platform using Wappalyzer
                try:
                    wappalyzer = Wappalyzer.latest()
                    webpage = WebPage.new_from_url(url)
                    technologies = wappalyzer.analyze(webpage)
                    site_info["platform"] = ', '.join(technologies)
                except Exception as e:
                    site_info["platform"] = f"Error detecting platform: {e}"

                # Get WHOIS server info
                try:
                    domain_info = whois.whois(url)
                    site_info["server_info"] = domain_info.get('name_servers', 'N/A')
                except Exception as e:
                    site_info["server_info"] = f"Error fetching WHOIS info: {e}"

                # Perform DNS lookup
                try:
                    dns_resolver = dns.resolver.Resolver()
                    dns_info = dns_resolver.resolve(url.replace('https://', '').replace('http://', '').split('/')[0])
                    site_info["dns_info"] = ', '.join([str(rdata) for rdata in dns_info])
                except Exception as e:
                    site_info["dns_info"] = f"Error fetching DNS info: {e}"

                # Check for VBV (Verified by Visa)
                vbv_keywords = ['verified by visa', '3d secure', 'vbv']
                site_info["vbv"] = any(keyword in html_content.lower() for keyword in vbv_keywords)

                # Check for authentication gate by looking for HTTP 401 or 403 status codes
                site_info["auth_gate"] = response.status in [401, 403]

                # Get SSL certificate information
                domain = url.replace('https://', '').replace('http://', '').split('/')[0]
                site_info["ssl_info"] = await get_ssl_info(domain)

                site_info["time_taken"] = round(time.time() - start_time, 2)
    except asyncio.TimeoutError:
        site_info["error"] = "Connection timed out"
    except aiohttp.ClientError as e:
        site_info["error"] = f"Error making request: {e}"

    return site_info

# Format the result based on the provided template
def format_result(site_info):
    ssl_info = site_info.get('ssl_info', {})
    
    # Format each section as specified
    formatted_result = f"""
┏━━━━━━━⍟
┃ 𝗜𝗻𝗳𝗼𝗿𝗺𝗮𝘁𝗶𝗼𝗻 𝗙𝗲𝘁𝗰𝗵𝗲𝗱 ✅
┗━━━━━━━━━━━━⊛
• 𝗦𝗶𝘁𝗲 ➜ {site_info['site']}

• 𝗚𝗮𝘁𝗲𝘄𝗮𝘆𝘀 ➜ {', '.join(site_info['payment_methods']) if site_info['payment_methods'] else "❌ No Payment Gateways Detected"}

• 𝗖𝗮𝗽𝘁𝗰𝗵𝗮 ➜ {"TRUE" if site_info['captcha'] else "FALSE"} 🔥

• 𝗖𝗹𝗼𝘂𝗱𝗳𝗹𝗮𝗿𝗲 ➜ {"TRUE" if site_info['cloudflare'] else "FALSE"} 🔥

• 𝗔𝘂𝘁𝗵 𝗚𝗮𝘁𝗲 ➜ {"TRUE" if site_info['auth_gate'] else "FALSE"} 🔐

• 𝗩𝗲𝗿𝗶𝗳𝗶𝗲𝗱 𝗯𝘆 𝗩𝗶𝘀𝗮 ➜ {"TRUE" if site_info['vbv'] else "FALSE"} 💳

━━━━━━━━━━━━━━━
🔐 **𝗦𝗦𝗟 𝗗𝗲𝘁𝗮𝗶𝗹𝘀**:
• **Issuer**: {ssl_info.get('issuer', 'N/A')}
• **Subject**: {ssl_info.get('subject', 'N/A')}
• **Valid From**: {ssl_info.get('valid_from', 'N/A')}
• **Valid To**: {ssl_info.get('valid_to', 'N/A')}

🧩 **𝗣𝗹𝗮𝘁𝗳𝗼𝗿𝗺 & 𝗧𝗲𝗰𝗵𝗻𝗼𝗹𝗼𝗴𝗶𝗲𝘀** ➜ {site_info.get('platform', '❌ No Platform Information Detected')}

🌍 **𝗗𝗡𝗦 𝗜𝗻𝗳𝗼** ➜ {site_info.get('dns_info', '❌ No DNS Information Detected')}

━━━━━━━━━━━━━━━
◈ 𝗧𝗶𝗺𝗲 𝗧𝗮𝗸𝗲𝗻 : {site_info.get('time_taken', 'N/A')}s
"""
    
    return formatted_result

# Handler for the /start command
@router.message(Command("start"))
async def handle_start(message: Message):
    welcome_text = '''
Welcome to the Website Checker Bot! 🛡️

Here you can check the details of websites such as platform, payment methods, server info, and much more. 

Use the /cmd command to see a list of all available commands.
    '''
    await message.answer(welcome_text)

# Handler to display all available commands /cmd
@router.message(Command("cmd"))
async def handle_cmd(message: Message):
    cmd_text = '''
🛡️ Available Commands:
/start - Welcome message with bot description.
/cmd - List of all available commands and their usage.
/gate <website_url> - Check details for a single website.
/mgate - Check details for up to 20 websites (one URL per line).
/gatetxt - Upload a .txt file containing URLs to check up to 300 websites.
    '''
    await message.answer(cmd_text)

# Handler to check a single website /gate <website_url>
@router.message(Command("gate"))
async def handle_gate(message: Message):
    try:
        url = message.text.split()[1]
        site_info = await fetch_site_info(url)
        await message.answer(format_result(site_info))
    except IndexError:
        await message.answer("Please provide a valid URL: /gate <website_url>")
    except Exception as e:
        await message.answer(f"Error: {e}")

# Main function to run the bot
async def main():
    dp.include_router(router)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == '__main__':
    try:
        # Ensure the correct event loop is used
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If the loop is already running, use it
            task = loop.create_task(main())
        else:
            # Otherwise, run the event loop
            asyncio.run(main())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
