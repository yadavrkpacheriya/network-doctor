# -*- coding: utf-8 -*-
"""Usage history: which device used which app / website, how much and when - and what that says about work.

Sources (all optional, the more the better):
  * NetFlow from the router (Live monitor): bytes per device and internet address.
  * DNS names: the router's DNS cache (router login in Setup) and / or the website firewall on this PC tell
    which web site name an internet address belongs to, so YouTube is not just "Google".
Everything is kept on this PC in usage.db (SQLite), 120 days.

Each app / site is Productive, Neutral or Unproductive. Built-in rules cover the common ones; the user can
change any of them, and Network Doctor uses the user's choice from then on.

"Learning": baselines per weekday and hour are rebuilt from the history every time, so peaks, unusual
devices and habits (which apps fill the line at the busy hours, day after day) are judged against what is
normal for this office, and the advice changes as the office changes.
"""

import collections
import datetime as dt
import ipaddress
import json
import os
import re
import sqlite3
import statistics
import threading
import time

WORK, NEUTRAL, PERSONAL = "work", "neutral", "personal"
CAT_LABEL = {WORK: "Productive", NEUTRAL: "Neutral", PERSONAL: "Unproductive"}
SLOT = 300            # seconds: a device counts as "using" an app in a 5-minute slot with at least ACTIVE_BYTES
ACTIVE_BYTES = 150_000
KEEP_DAYS = 120

PORT_RULES = {25: ("Email", WORK), 465: ("Email", WORK), 587: ("Email", WORK), 993: ("Email", WORK),
              995: ("Email", WORK), 143: ("Email", WORK), 110: ("Email", WORK), 3389: ("Remote Desktop", WORK),
              53: ("DNS", NEUTRAL), 853: ("DNS", NEUTRAL), 123: ("Time sync", NEUTRAL),
              1194: ("VPN", NEUTRAL), 51820: ("VPN", NEUTRAL), 500: ("VPN", NEUTRAL), 4500: ("VPN", NEUTRAL),
              6881: ("BitTorrent", PERSONAL), 6889: ("BitTorrent", PERSONAL), 51413: ("BitTorrent", PERSONAL)}

TWO_LEVEL = {"co.in", "gov.in", "nic.in", "org.in", "net.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in",
             "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.sg", "com.br", "co.za",
             "com.cn", "com.hk", "co.nz", "com.my", "co.id", "com.tr", "com.mx"}


UMBRELLA = {"google.com", "microsoft.com", "amazon.com", "apple.com", "yahoo.com", "live.com", "zoho.com"}


def site_of(name):
    """'rr3---sn-a5m.googlevideo.com' -> 'googlevideo.com'; 'mail.yahoo.co.in' -> 'yahoo.co.in'."""
    n = (name or "").strip(".").lower()
    if not n or re.fullmatch(r"[\d.]+", n):
        return ""
    p = n.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in TWO_LEVEL:
        return ".".join(p[-3:])
    base = ".".join(p[-2:])
    if base in UMBRELLA and len(p) >= 3 and p[-3] not in ("www", "api", "cdn", "static"):
        return ".".join(p[-3:])  # mail.google.com and drive.google.com are different things
    return base


# ==========================================================================
# App catalogue: which web addresses belong to which app. Matched on the end of the full DNS name
# (m.facebook.com -> facebook.com), the longest match wins, so youtubei.googleapis.com is YouTube while
# www.googleapis.com stays "Google (other)". Facebook, Instagram, WhatsApp and Messenger are kept apart.
# (app, category, group, [domain endings])
# ==========================================================================
CATALOG = [
    # ---- Meta: four different apps on the same company's servers
    ("WhatsApp", NEUTRAL, "Messaging", ["whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.biz"]),
    ("Instagram", PERSONAL, "Social media", ["instagram.com", "cdninstagram.com", "ig.me", "instagr.am"]),
    ("Facebook", PERSONAL, "Social media", ["facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me",
                                            "fbsbx.com", "fb.gg", "facebook.in"]),
    ("Messenger", PERSONAL, "Messaging", ["messenger.com", "m.me"]),
    ("Threads", PERSONAL, "Social media", ["threads.net", "threads.com"]),
    # ---- Google: each service by its own address
    ("YouTube", PERSONAL, "Video", ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
                                     "youtube-nocookie.com", "youtubei.googleapis.com", "yt3.ggpht.com",
                                     "youtube.googleapis.com", "ytstatic.com"]),
    ("YouTube Music", PERSONAL, "Music", ["music.youtube.com"]),
    ("Google Drive / Docs", WORK, "Cloud storage & office", [
        "drive.google.com", "docs.google.com", "sheets.google.com", "slides.google.com", "forms.google.com",
        "drive.googleapis.com", "docs.googleusercontent.com", "drive.usercontent.google.com",
        "drivefrontend-pa.clients6.google.com", "content.googleapis.com"]),
    ("Gmail", WORK, "Email", ["mail.google.com", "gmail.com", "inbox.google.com", "gmail.googleapis.com"]),
    ("Google Meet", WORK, "Video calls", ["meet.google.com", "meet.googleapis.com", "hangouts.google.com"]),
    ("Google Calendar / Contacts", WORK, "Cloud storage & office", ["calendar.google.com", "contacts.google.com"]),
    ("Google Photos", PERSONAL, "Photos", ["photos.google.com", "photos.googleapis.com",
                                           "photoslibrary.googleapis.com"]),
    ("Google Play Store", NEUTRAL, "App stores", ["play.google.com", "play.googleapis.com",
                                                            "play-fe.googleapis.com", "android.clients.google.com",
                                                            "play-lh.googleusercontent.com"]),
    ("Google Maps", NEUTRAL, "Maps & travel", ["maps.google.com", "maps.googleapis.com", "maps.gstatic.com",
                                               "maps.app.goo.gl"]),
    ("Google Pay", NEUTRAL, "Banking & payments", ["pay.google.com", "payments.google.com"]),
    ("Gemini (Google AI)", WORK, "AI tools", ["gemini.google.com", "bard.google.com",
                                              "generativelanguage.googleapis.com"]),
    ("Google Translate", WORK, "AI tools", ["translate.google.com", "translate.googleapis.com"]),
    ("Google Search & other", NEUTRAL, "Search & system", ["google.com", "google.co.in", "googleapis.com",
                                                           "gstatic.com", "googleusercontent.com", "ggpht.com",
                                                           "gvt1.com", "gvt2.com", "1e100.net", "goo.gl",
                                                           "googletagservices.com", "withgoogle.com"]),
    # ---- Microsoft
    ("Microsoft Teams", WORK, "Video calls", ["teams.microsoft.com", "teams.live.com", "teams.cdn.office.net",
                                              "teams.events.data.microsoft.com", "lync.com", "skype.com",
                                              "skypeforbusiness.com", "trouter.teams.microsoft.com"]),
    ("Outlook / Exchange", WORK, "Email", ["outlook.office.com", "outlook.office365.com", "outlook.live.com",
                                           "outlook.com", "hotmail.com", "protection.outlook.com"]),
    ("OneDrive / SharePoint", WORK, "Cloud storage & office", ["onedrive.live.com", "onedrive.com", "1drv.com",
                                                               "1drv.ms", "sharepoint.com", "sharepointonline.com",
                                                               "storage.live.com"]),
    ("Microsoft 365 (Office)", WORK, "Cloud storage & office", ["office.com", "office.net", "office365.com",
                                                                "officeapps.live.com", "microsoft365.com",
                                                                "microsoftonline.com", "msauth.net", "msftauth.net",
                                                                "cloud.microsoft"]),
    ("Copilot / Bing AI", WORK, "AI tools", ["copilot.microsoft.com", "copilot.cloud.microsoft", "sydney.bing.com"]),
    ("Windows Update", NEUTRAL, "Updates & drivers", [
        "windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "download.windowsupdate.com",
        "windowsupdate.microsoft.com", "dl.delivery.mp.microsoft.com", "tlu.dl.delivery.mp.microsoft.com",
        "emdl.ws.microsoft.com", "wustat.windows.com", "ntservicepack.microsoft.com"]),
    ("Microsoft Office updates", NEUTRAL, "Updates & drivers", ["officecdn.microsoft.com",
                                                                "officecdn.microsoft.com.edgesuite.net",
                                                                "officecdnmac.microsoft.com"]),
    ("Windows Defender updates", NEUTRAL, "Updates & drivers", ["definitionupdates.microsoft.com",
                                                                "wdcp.microsoft.com", "wdcpalt.microsoft.com",
                                                                "smartscreen-prod.microsoft.com",
                                                                "unitedstates.cp.wd.microsoft.com"]),
    ("Edge browser updates", NEUTRAL, "Updates & drivers", ["msedge.api.cdp.microsoft.com", "edge.microsoft.com"]),
    ("Microsoft Store", NEUTRAL, "App stores", ["storeedgefd.dsx.mp.microsoft.com",
                                                          "displaycatalog.mp.microsoft.com", "apps.microsoft.com"]),
    ("Xbox", PERSONAL, "Games", ["xboxlive.com", "xbox.com", "xboxservices.com", "gamepass.com"]),
    ("MSN news", PERSONAL, "News & sports", ["msn.com", "msn.cn"]),
    ("Bing search", NEUTRAL, "Search & system", ["bing.com", "bing.net"]),
    ("Microsoft (other)", NEUTRAL, "Search & system", ["microsoft.com", "windows.com", "windows.net", "live.com",
                                                       "live.net", "azure.com", "azureedge.net", "msedge.net",
                                                       "msecnd.net", "aka.ms", "microsoftonline-p.com",
                                                       "msftncsi.com", "visualstudio.com"]),
    # ---- AI tools
    ("ChatGPT", WORK, "AI tools", ["chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com"]),
    ("Claude", WORK, "AI tools", ["claude.ai", "anthropic.com", "claudeusercontent.com"]),
    ("Perplexity", WORK, "AI tools", ["perplexity.ai"]),
    ("DeepSeek", WORK, "AI tools", ["deepseek.com"]),
    # ---- video & OTT
    ("Netflix", PERSONAL, "Video", ["netflix.com", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxso.net",
                                    "nflxext.com"]),
    ("Amazon Prime Video", PERSONAL, "Video", ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net",
                                              "amazonvideo.com", "pv-cdn.net", "media-amazon.com.akamaized.net"]),
    ("JioHotstar", PERSONAL, "Video", ["hotstar.com", "hotstarext.com", "jiocinema.com", "jiohotstar.com",
                                       "hscdn.com"]),
    ("SonyLIV", PERSONAL, "Video", ["sonyliv.com"]),
    ("ZEE5", PERSONAL, "Video", ["zee5.com", "zee5.in"]),
    ("MX Player", PERSONAL, "Video", ["mxplayer.in", "mxplay.com"]),
    ("Other Indian OTT", PERSONAL, "Video", ["voot.com", "altbalaji.com", "erosnow.com", "hoichoi.tv", "aha.video",
                                            "sunnxt.com", "airtelxstream.in", "shemaroome.com", "discoveryplus.in",
                                            "lionsgateplay.com", "chaupal.tv", "stage.in"]),
    ("Twitch", PERSONAL, "Video", ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net"]),
    ("Vimeo", NEUTRAL, "Video", ["vimeo.com", "vimeocdn.com"]),
    ("Dailymotion", PERSONAL, "Video", ["dailymotion.com", "dmcdn.net"]),
    ("TikTok", PERSONAL, "Short videos", ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com",
                                          "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "musical.ly",
                                          "tiktokcdn-eu.com"]),
    ("Moj / ShareChat", PERSONAL, "Short videos", ["sharechat.com", "mojapp.in", "moj.app", "sharechat.co"]),
    ("Josh", PERSONAL, "Short videos", ["myjosh.in", "joshapp.in"]),
    ("Chingari / Roposo", PERSONAL, "Short videos", ["chingari.io", "roposo.com"]),
    # ---- social & forums
    ("Snapchat", PERSONAL, "Social media", ["snapchat.com", "sc-cdn.net", "snap-dev.net", "snapkit.com",
                                            "sc-static.net", "feelinsonice.appspot.com"]),
    ("X / Twitter", PERSONAL, "Social media", ["twitter.com", "x.com", "twimg.com", "t.co", "twttr.com"]),
    ("LinkedIn", WORK, "Business & jobs", ["linkedin.com", "licdn.com", "lnkd.in"]),
    ("Reddit", PERSONAL, "Social media", ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]),
    ("Pinterest", PERSONAL, "Social media", ["pinterest.com", "pinimg.com", "pinterest.in"]),
    ("Quora", PERSONAL, "Social media", ["quora.com", "quoracdn.net"]),
    ("Tumblr", PERSONAL, "Social media", ["tumblr.com"]),
    ("Koo", PERSONAL, "Social media", ["kooapp.com"]),
    ("Dating apps", PERSONAL, "Social media", ["tinder.com", "gotinder.com", "bumble.com", "bumbleapp.com",
                                               "hinge.co", "aisle.co", "trulymadly.com"]),
    # ---- messaging & calls
    ("Telegram", PERSONAL, "Messaging", ["telegram.org", "t.me", "telegram.me", "telesco.pe", "cdn-telegram.org",
                                         "tdesktop.com"]),
    ("Signal", NEUTRAL, "Messaging", ["signal.org", "whispersystems.org", "signal.art"]),
    ("Discord", PERSONAL, "Messaging", ["discord.com", "discord.gg", "discordapp.com", "discordapp.net",
                                        "discord.media"]),
    ("Slack", WORK, "Messaging", ["slack.com", "slack-edge.com", "slack-msgs.com", "slack-imgs.com"]),
    ("Zoom", WORK, "Video calls", ["zoom.us", "zoom.com", "zoomgov.com", "zoomcdn.com"]),
    ("Webex", WORK, "Video calls", ["webex.com", "wbx2.com", "ciscospark.com"]),
    ("GoTo Meeting", WORK, "Video calls", ["gotomeeting.com", "goto.com", "logmein.com"]),
    ("Truecaller", NEUTRAL, "Messaging", ["truecaller.com", "tcaller.com"]),
    ("AnyDesk", WORK, "Remote access", ["anydesk.com", "net.anydesk.com"]),
    ("TeamViewer", WORK, "Remote access", ["teamviewer.com", "tvcdn.de"]),
    ("Chrome Remote Desktop", WORK, "Remote access", ["remotedesktop.google.com",
                                                      "remotedesktop-pa.googleapis.com"]),
    # ---- music
    ("Spotify", PERSONAL, "Music", ["spotify.com", "scdn.co", "spotifycdn.com", "pscdn.co", "spotify.design",
                                    "spoti.fi"]),
    ("JioSaavn", PERSONAL, "Music", ["saavn.com", "jiosaavn.com", "saavncdn.com"]),
    ("Gaana", PERSONAL, "Music", ["gaana.com", "gaanacdn.com"]),
    ("Wynk Music", PERSONAL, "Music", ["wynk.in"]),
    ("Amazon Music", PERSONAL, "Music", ["music.amazon.in", "music.amazon.com", "amazonmusic.com"]),
    ("Apple Music", PERSONAL, "Music", ["music.apple.com"]),
    ("SoundCloud", PERSONAL, "Music", ["soundcloud.com", "sndcdn.com"]),
    ("Pocket FM / audio stories", PERSONAL, "Music", ["pocketfm.com", "pocketfm.in", "kukufm.com"]),
    # ---- games & betting
    ("Steam", PERSONAL, "Games", ["steampowered.com", "steamcommunity.com", "steamcontent.com", "steamstatic.com",
                                  "steamserver.net", "valvesoftware.com", "steamusercontent.com"]),
    ("Epic Games / Fortnite", PERSONAL, "Games", ["epicgames.com", "epicgames.dev", "unrealengine.com",
                                                  "fortnite.com", "epicgamescdn.com"]),
    ("BGMI / PUBG", PERSONAL, "Games", ["pubg.com", "battlegroundsmobileindia.com", "krafton.com", "igamecj.com",
                                        "proximabeta.net", "pubgmobile.com", "gcloudsdk.com"]),
    ("Free Fire", PERSONAL, "Games", ["garena.com", "freefiremobile.com", "garenanow.com", "ff.garena.com"]),
    ("Riot Games / Valorant", PERSONAL, "Games", ["riotgames.com", "leagueoflegends.com", "playvalorant.com",
                                                  "riotcdn.net"]),
    ("Roblox", PERSONAL, "Games", ["roblox.com", "rbxcdn.com", "rbx.com"]),
    ("Minecraft", PERSONAL, "Games", ["minecraft.net", "mojang.com"]),
    ("PlayStation", PERSONAL, "Games", ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"]),
    ("EA / Origin", PERSONAL, "Games", ["ea.com", "origin.com", "eapc.com"]),
    ("Blizzard / Battle.net", PERSONAL, "Games", ["battle.net", "blizzard.com"]),
    ("Supercell (Clash, Brawl)", PERSONAL, "Games", ["supercell.com", "supercell.net", "clashofclans.com"]),
    ("Chess.com", PERSONAL, "Games", ["chess.com", "chesscomfiles.com"]),
    ("Mobile games (other)", PERSONAL, "Games", ["miniclip.com", "king.com", "candycrush.com", "unity3d.com",
                                                 "ludoking.com", "gameloft.com", "playrix.com",
                                                 "zynga.com", "moonfroglabs.com"]),
    ("Fantasy / real-money games", PERSONAL, "Games", ["dream11.com", "my11circle.com", "mpl.live",
                                                       "winzogames.com", "rummycircle.com", "jungleerummy.com",
                                                       "a23.com", "pokerbaazi.com", "zupee.com", "howzat.com",
                                                       "probo.in", "sportsbaazi.com"]),
    # ---- shopping & food
    ("Amazon shopping", PERSONAL, "Shopping", ["amazon.in", "amazon.com", "media-amazon.com",
                                               "ssl-images-amazon.com", "images-amazon.com", "amazon.co.in"]),
    ("Flipkart", PERSONAL, "Shopping", ["flipkart.com", "flixcart.com", "flipkart.net", "fkcdn.com"]),
    ("Myntra", PERSONAL, "Shopping", ["myntra.com", "myntassets.com"]),
    ("Meesho", PERSONAL, "Shopping", ["meesho.com", "meeshosupplyassets.com"]),
    ("Other shopping", PERSONAL, "Shopping", ["ajio.com", "nykaa.com", "nykaafashion.com", "snapdeal.com",
                                              "tatacliq.com", "jiomart.com", "shopsy.in", "firstcry.com",
                                              "lenskart.com", "croma.com", "reliancedigital.in", "pepperfry.com",
                                              "urbanladder.com", "purplle.com", "mamaearth.in", "boat-lifestyle.com",
                                              "aliexpress.com", "shein.in", "temu.com", "olx.in"]),
    ("Groceries (Blinkit, Zepto...)", PERSONAL, "Shopping", ["blinkit.com", "grofers.com", "zeptonow.com",
                                                             "bigbasket.com", "swiggyinstamart.com", "dunzo.com"]),
    ("Swiggy", PERSONAL, "Food delivery", ["swiggy.com", "swiggy.in"]),
    ("Zomato", PERSONAL, "Food delivery", ["zomato.com", "zmtcdn.com", "zomato.in"]),
    # ---- news & sports
    ("Cricket scores", PERSONAL, "News & sports", ["cricbuzz.com", "espncricinfo.com", "iplt20.com",
                                                   "bcci.tv", "crictracker.com", "fancode.com"]),
    ("News sites", PERSONAL, "News & sports", ["indiatimes.com", "timesofindia.com", "ndtv.com",
                                               "hindustantimes.com", "indianexpress.com", "thehindu.com",
                                               "news18.com", "aajtak.in", "abplive.com", "zeenews.india.com",
                                               "dailyhunt.in", "inshorts.com", "jagran.com", "bhaskar.com",
                                               "amarujala.com", "livehindustan.com", "moneycontrol.com",
                                               "economictimes.com", "livemint.com", "business-standard.com",
                                               "bbc.com", "bbc.co.uk", "cnn.com", "indiatoday.in"]),
    ("Stock trading apps", PERSONAL, "Banking & payments", ["zerodha.com", "kite.zerodha.com", "groww.in",
                                                            "upstox.com", "angelone.in", "5paisa.com", "dhan.co",
                                                            "paytmmoney.com", "sharekhan.com"]),
    # ---- work: government, business, banking, office tools
    ("GST portal", WORK, "Government", ["gst.gov.in", "ewaybillgst.gov.in", "einvoice1.gst.gov.in",
                                        "gstsystem.gov.in"]),
    ("Income tax / TDS", WORK, "Government", ["incometax.gov.in", "incometaxindiaefiling.gov.in", "tdscpc.gov.in",
                                              "tin-nsdl.com", "protean-tinpan.com", "onlineservices.nsdl.com"]),
    ("MCA / company affairs", WORK, "Government", ["mca.gov.in"]),
    ("EPFO / ESIC", WORK, "Government", ["epfindia.gov.in", "esic.gov.in", "esic.nic.in", "unifiedportal-mem.epfindia.gov.in"]),
    ("Customs / DGFT", WORK, "Government", ["icegate.gov.in", "dgft.gov.in", "cbic.gov.in"]),
    ("GeM / tenders", WORK, "Government", ["gem.gov.in", "eprocure.gov.in", "etenders.gov.in",
                                           "eproc.rajasthan.gov.in", "tenderwizard.com", "tendertiger.com"]),
    ("Government portals (other)", WORK, "Government", ["gov.in", "nic.in", "udyamregistration.gov.in",
                                                        "uidai.gov.in", "digilocker.gov.in", "rajasthan.gov.in"]),
    ("Tally", WORK, "Accounts & ERP", ["tallysolutions.com", "tallyprime.com", "tally.in"]),
    ("Zoho", WORK, "Accounts & ERP", ["zoho.com", "zoho.in", "zohocdn.com", "zohostatic.com", "zohopublic.com"]),
    ("Business software (cloud)", WORK, "Accounts & ERP", [
        "salesforce.com", "force.com", "hubspot.com", "hsforms.com", "freshworks.com", "freshdesk.com",
        "freshsales.io", "odoo.com", "sap.com", "oraclecloud.com", "netsuite.com", "busy.in", "marg.com",
        "margcompusoft.com", "vyaparapp.in", "khatabook.com", "mybillbook.in", "cleartax.in", "clear.in",
        "razorpayx.com", "quickbooks.com", "intuit.com", "keka.com", "greythr.com", "zinghr.com", "darwinbox.in"]),
    ("IndiaMART / B2B", WORK, "Business & jobs", ["indiamart.com", "imimg.com", "tradeindia.com", "justdial.com",
                                                  "exportersindia.com", "alibaba.com", "made-in-china.com",
                                                  "udaan.com"]),
    ("Banking", WORK, "Banking & payments", ["hdfcbank.com", "hdfc.com", "icicibank.com", "onlinesbi.sbi",
                                             "sbi.co.in", "onlinesbi.com", "axisbank.com", "kotak.com",
                                             "kotak.bank.in", "yesbank.in", "pnbindia.in", "netpnb.com",
                                             "bankofbaroda.in", "bobibanking.com", "canarabank.com",
                                             "unionbankofindia.co.in", "idfcfirstbank.com", "indusind.com",
                                             "federalbank.co.in", "rblbank.com", "aubank.in", "bank.in"]),
    ("Payments (UPI, gateways)", NEUTRAL, "Banking & payments", ["paytm.com", "paytm.in", "phonepe.com",
                                                                 "razorpay.com", "npci.org.in", "bhimupi.org.in",
                                                                 "cashfree.com", "payu.in", "ccavenue.com",
                                                                 "billdesk.com", "mobikwik.com", "cred.club"]),
    ("Logistics & courier", WORK, "Business & jobs", ["delhivery.com", "bluedart.com", "dtdc.in", "dtdc.com",
                                                      "shiprocket.in", "xpressbees.com", "ecomexpress.in",
                                                      "vrlgroup.in", "tcil.com", "gati.com", "safexpress.com",
                                                      "indiapost.gov.in", "fedex.com", "dhl.com"]),
    ("Dropbox", WORK, "Cloud storage & office", ["dropbox.com", "dropboxapi.com", "dropboxusercontent.com",
                                                 "dropboxstatic.com", "db.tt"]),
    ("WeTransfer / file sharing", WORK, "Cloud storage & office", ["wetransfer.com", "we.tl", "box.com",
                                                                   "boxcdn.net", "sendanywhere.com"]),
    ("MEGA (file sharing)", PERSONAL, "Cloud storage & office", ["mega.nz", "mega.io", "mega.co.nz"]),
    ("Canva", WORK, "Design & CAD", ["canva.com", "canva.cn"]),
    ("Autodesk / CAD", WORK, "Design & CAD", ["autodesk.com", "autodesk360.com", "solidworks.com", "3ds.com",
                                              "ptc.com", "onshape.com", "sketchup.com", "trimble.com"]),
    ("Adobe", WORK, "Design & CAD", ["adobe.com", "adobe.io", "adobelogin.com", "adobecc.com", "typekit.net",
                                     "acrobat.com"]),
    ("Dev tools (GitHub...)", WORK, "Business & jobs", ["github.com", "githubusercontent.com", "githubassets.com",
                                                        "gitlab.com", "atlassian.net", "atlassian.com",
                                                        "bitbucket.org", "stackoverflow.com", "sstatic.net",
                                                        "npmjs.org", "pypi.org", "pythonhosted.org"]),
    ("Email (other)", NEUTRAL, "Email", ["mail.yahoo.com", "yahoo.com", "rediffmail.com", "rediff.com",
                                         "mail.zoho.com", "mail.zoho.in", "proton.me", "protonmail.com"]),
    ("Job portals", PERSONAL, "Business & jobs", ["naukri.com", "naukimg.com", "indeed.com", "indeed.co.in",
                                                  "foundit.in", "monsterindia.com", "shine.com", "apna.co",
                                                  "internshala.com", "glassdoor.com", "glassdoor.co.in"]),
    ("Online learning", NEUTRAL, "Learning", ["udemy.com", "udemycdn.com", "coursera.org", "byjus.com",
                                              "unacademy.com", "khanacademy.org", "nptel.ac.in", "swayam.gov.in",
                                              "duolingo.com", "physicswallah.com", "pw.live"]),
    ("Travel booking", NEUTRAL, "Maps & travel", ["irctc.co.in", "makemytrip.com", "goibibo.com", "ixigo.com",
                                                  "redbus.in", "cleartrip.com", "yatra.com", "easemytrip.com",
                                                  "booking.com", "airbnb.com", "airindia.com", "goindigo.in",
                                                  "uber.com", "olacabs.com", "rapido.bike"]),
    # ---- system, security, cameras, ads
    ("Apple / iCloud", NEUTRAL, "App stores", ["icloud.com", "apple.com", "mzstatic.com", "aaplimg.com",
                                                         "cdn-apple.com", "apple-cloudkit.com", "itunes.com",
                                                         "icloud-content.com"]),
    ("Phone software updates (Samsung, Xiaomi...)", NEUTRAL, "Updates & drivers", [
        "samsung.com", "samsungcloud.com", "samsungosp.com", "xiaomi.com", "miui.com", "mi.com",
        "oppomobile.com", "heytapmobile.com", "coloros.com", "vivo.com.cn", "vivoglobal.com", "realme.com",
        "oneplus.com", "oneplus.net", "motorola.com", "hihonor.com"]),
    ("Dell drivers & support", NEUTRAL, "Updates & drivers", ["dell.com", "dellcdn.com", "dellsupportcenter.com",
                                                              "downloads.dell.com", "dl.dell.com", "dell.co.in",
                                                              "delltechnologies.com"]),
    ("Lenovo drivers & support", NEUTRAL, "Updates & drivers", ["lenovo.com", "lenovomm.com", "lenovo.co.in",
                                                                "lenovovantage.com", "lenovo.com.cn"]),
    ("HP drivers & support", NEUTRAL, "Updates & drivers", ["hp.com", "hpsmart.com", "hpeprint.com",
                                                            "hpconnected.com", "hpicorp.net", "hpcloud.hp.com",
                                                            "hp.io"]),
    ("Intel drivers", NEUTRAL, "Updates & drivers", ["intel.com", "intel.cn", "intel.in"]),
    ("NVIDIA / AMD graphics drivers", NEUTRAL, "Updates & drivers", ["nvidia.com", "geforce.com", "nvidia.cn",
                                                                     "amd.com", "amd.cn"]),
    ("Other PC makers' drivers", NEUTRAL, "Updates & drivers", ["realtek.com", "asus.com", "asus.com.cn",
                                                                "acer.com", "msi.com", "gigabyte.com",
                                                                "asrock.com", "toshiba.com", "dynabook.com",
                                                                "microsoftsurface.com", "logitech.com",
                                                                "logi.com", "tp-link.com", "seagate.com",
                                                                "westerndigital.com", "wdc.com", "sandisk.com",
                                                                "kingston.com", "crucial.com"]),
    ("Printer drivers & cloud", NEUTRAL, "Updates & drivers", ["canon.com", "canon.co.in", "epson.com",
                                                               "epson.co.in", "epson.net", "brother.com",
                                                               "brother.in", "brother.co.jp", "kyoceradocumentsolutions.com",
                                                               "ricoh.com", "xerox.com", "konicaminolta.com",
                                                               "sharp.co.jp", "pantum.com"]),
    ("Chrome browser updates", NEUTRAL, "Updates & drivers", ["dl.google.com", "update.googleapis.com",
                                                              "edgedl.me.gvt1.com", "redirector.gvt1.com",
                                                              "tools.google.com"]),
    ("Firefox / other browser updates", NEUTRAL, "Updates & drivers", ["mozilla.org", "mozilla.net",
                                                                       "mozilla.com", "firefox.com", "opera.com",
                                                                       "operacdn.com", "brave.com",
                                                                       "bravesoftware.com"]),
    ("Software downloads (other)", NEUTRAL, "Updates & drivers", ["java.com", "sourceforge.net", "filehippo.com",
                                                                  "softonic.com", "uptodown.com", "ninite.com",
                                                                  "7-zip.org", "videolan.org", "winrar.com",
                                                                  "rarlab.com", "notepad-plus-plus.org",
                                                                  "apkpure.com", "apkmirror.com"]),
    ("Antivirus updates", NEUTRAL, "Security", ["quickheal.com", "quickheal.co.in", "k7computing.com",
                                                "avast.com", "avcdn.net", "avg.com", "kaspersky.com",
                                                "kaspersky-labs.com", "eset.com", "mcafee.com", "norton.com",
                                                "symantec.com", "bitdefender.com", "bitdefender.net",
                                                "sophos.com", "trendmicro.com", "malwarebytes.com",
                                                "escanav.com", "seqrite.com", "npav.net"]),
    ("CCTV cloud", NEUTRAL, "Cameras", ["hik-connect.com", "hikvision.com", "ezvizlife.com", "ezviz.com",
                                        "hik-partner.com", "dahuasecurity.com", "imoulife.com", "easy4ip.com",
                                        "cpplusworld.com", "cpplusworld.in", "uniview.com", "tplinkcloud.com",
                                        "tapo.com", "qvis.co.in", "dlink.com", "mydlink.com", "yi-cam.com"]),
    ("Ads & trackers", NEUTRAL, "Ads & trackers", [
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
        "googletagmanager.com", "app-measurement.com", "adnxs.com", "amazon-adsystem.com", "criteo.com",
        "taboola.com", "outbrain.com", "adsrvr.org", "moatads.com", "scorecardresearch.com", "inmobi.com",
        "applovin.com", "unityads.unity3d.com", "appsflyer.com", "adjust.com", "branch.io", "crashlytics.com",
        "firebaselogging-pa.googleapis.com", "clevertap-prod.com", "moengage.com", "onesignal.com"]),
    ("CDN (various)", NEUTRAL, "Search & system", ["akamai.net", "akamaihd.net", "akamaized.net",
                                                   "akamaiedge.net", "edgekey.net", "edgesuite.net", "akamai.com",
                                                   "cloudflare.com", "cloudflare.net", "cloudfront.net",
                                                   "fastly.net", "fastlylb.net", "edgecastcdn.net", "cdn77.org",
                                                   "jsdelivr.net", "bunnycdn.com", "b-cdn.net", "llnwd.net",
                                                   "stackpathdns.com"]),
    ("Amazon cloud (AWS)", NEUTRAL, "Search & system", ["amazonaws.com", "aws.amazon.com", "awsstatic.com"]),
    ("Internet checks / time", NEUTRAL, "Search & system", ["msftconnecttest.com", "connectivitycheck.gstatic.com",
                                                            "pool.ntp.org", "time.windows.com", "ntp.org",
                                                            "captive.apple.com", "time.google.com"]),
]

# when only the address owner is known (no DNS name): honest, wider labels - never "Facebook" for all of Meta
ORG_HINTS = [
    (("meta platforms", "facebook"), "Meta (Facebook / Instagram / WhatsApp - name not known)", NEUTRAL),
    (("google",), "Google (service not known)", NEUTRAL), (("microsoft",), "Microsoft (other)", NEUTRAL),
    (("akamai", "cloudflare", "fastly", "edgecast", "limelight"), "CDN (various)", NEUTRAL),
    (("amazon",), "Amazon cloud (AWS)", NEUTRAL), (("apple",), "Apple / iCloud", NEUTRAL),
    (("netflix",), "Netflix", PERSONAL), (("bytedance", "tiktok"), "TikTok", PERSONAL),
    (("telegram",), "Telegram", PERSONAL), (("valve",), "Steam", PERSONAL), (("zoom",), "Zoom", WORK),
    (("hikvision",), "CCTV cloud", NEUTRAL), (("dahua",), "CCTV cloud", NEUTRAL),
]

APP_INFO = {}   # app -> (category, group)
SUFFIX = {}     # domain ending -> app
for _app, _cat, _grp, _doms in CATALOG:
    APP_INFO[_app] = (_cat, _grp)
    for _d in _doms:
        SUFFIX.setdefault(_d.lower(), _app)
for _app, _cat in [(a, c) for _, a, c in ORG_HINTS] + [(a, c) for a, c in PORT_RULES.values()]:
    APP_INFO.setdefault(_app, (_cat, "Other"))


# addresses whose service is in the middle of the name
NAME_PATTERNS = [(re.compile(r"(^|\.)doc-[\w-]+-docs\.googleusercontent\.com$"), "Google Drive / Docs"),
                 (re.compile(r"(^|\.)[\w-]+---sn-[\w-]+\.googlevideo\.com$"), "YouTube"),
                 (re.compile(r"(^|\.)[\w-]+---sn-[\w-]+\.gvt1\.com$"), "Chrome browser updates"),
                 (re.compile(r"(^|\.)web\.whatsapp\.com$"), "WhatsApp"),
                 (re.compile(r"(^|\.)[\w-]*instagram[\w-]*\.([\w-]+\.)*fbcdn\.net$"), "Instagram"),
                 (re.compile(r"(^|\.)whatsapp-cdn-shv[\w-]*\.fbcdn\.net$"), "WhatsApp")]


# Small "front door" addresses (login, page, chat) that Google / Meta share between their apps. When the router's
# DNS cache shows several apps for such an address and the device's own look-up is unknown, the traffic is
# shown under this name instead of being given to one app. Video (googlevideo.com) and app-own addresses
# (whatsapp.net, cdninstagram.com) are never shared, so the big traffic still goes to the right app.
SHARED_FRONTENDS = {a: "Google (shared address)" for a in ("Google Drive / Docs", "Gmail", "Google Meet",
                                                            "Google Calendar / Contacts", "Google Photos",
                                                            "Google Search & other", "YouTube", "Google Play Store",
                                                            "Google Maps", "Gemini (Google AI)")}
SHARED_FRONTENDS.update({a: "Meta (shared address)" for a in ("Facebook", "Instagram", "WhatsApp", "Messenger",
                                                               "Threads")})


def app_of_name(name):
    """App for a DNS name by the longest matching domain ending, or None."""
    n = (name or "").strip(".").lower()
    for rx, app in NAME_PATTERNS:
        if rx.search(n):
            return app
    p = n.split(".")
    for i in range(len(p) - 1):
        app = SUFFIX.get(".".join(p[i:]))
        if app:
            return app
    return None


PRETTY = [  # server names that say nothing to a person -> what they are
    (re.compile(r"1e100\.net|googleusercontent|google llc|\bgoogle\b"), "Google server (service not named)"),
    (re.compile(r"whatsapp-cdn|whatsapp"), "WhatsApp media"),
    (re.compile(r"instagram"), "Instagram media"),
    (re.compile(r"fbcdn\.net|facebook|meta platforms"), "Facebook / Meta CDN"),
    (re.compile(r"akamai"), "Akamai CDN (downloads, updates, video)"),
    (re.compile(r"cloudfront"), "Amazon CloudFront CDN"),
    (re.compile(r"amazonaws|amazon"), "Amazon Web Services (cloud)"),
    (re.compile(r"cloudflare"), "Cloudflare CDN"),
    (re.compile(r"msedge|microsoft|azure|windows\.net|office"), "Microsoft cloud"),
    (re.compile(r"fastly"), "Fastly CDN"),
    (re.compile(r"edgecast|edgio|limelight|llnw"), "CDN (Edgio)"),
    (re.compile(r"jio|reliance"), "Jio network"),
    (re.compile(r"airtel|bharti"), "Airtel network"),
]


def ptr_of(org):
    """The server's own host name at the start of the 'ptr owner' text the monitor passes."""
    t = (org or "").split()
    return t[0].lower() if t and "." in t[0] and re.search(r"[a-z]", t[0].lower()) else ""


def pretty_site(text):
    """'lcdelw-in-f113.1e100.net Google LLC' -> 'Google server (service not named)';
    'a23-55-245-233.deploy.static.akamaitechnologies.com' -> 'Akamai CDN ...'; real site names stay."""
    t = (text or "").strip()
    low = t.lower()
    if not t:
        return t
    looks_server = bool(re.search(r"\d+[-.]\d+|\b(in-f\d+|shv-|deploy|static|edge|cache|cdn|srv|node|rev)\b", low)) \
        or " " in t or low.endswith(("1e100.net", "fbcdn.net", "akamaitechnologies.com", "amazonaws.com",
                                     "cloudfront.net", "akamaiedge.net"))
    if not looks_server:
        return t
    for rx, nice in PRETTY:
        if rx.search(low):
            return nice
    host = ptr_of(t) or t
    return site_of(host) or t


def cache_pairs(rows):
    """(address, name) from the router's DNS cache. Follows CNAMEs back to the name the person typed:
    docs.google.com -> CNAME googlehosted.l.googleusercontent.com -> A 142.250.x.x gives docs.google.com."""
    back = {}
    for r in rows:
        if (r.get("type") or "").upper() == "CNAME" and r.get("data") and r.get("name"):
            back.setdefault(r["data"].strip(".").lower(), r["name"].strip(".").lower())
    out = []
    for r in rows:
        data = r.get("data", "")
        if r.get("type") not in ("A", None) or not re.fullmatch(r"[\d.]+", data or ""):
            continue
        n, seen = (r.get("name") or "").strip(".").lower(), set()
        while n in back and n not in seen:  # walk up the CNAME chain
            seen.add(n)
            n = back[n]
        out.append((data, n))
    return out


def group_of(app):
    return APP_INFO.get(app, (NEUTRAL, "Other"))[1]


def classify(name, org="", port=0, overrides=None, dept=""):
    """(app, category). name: DNS name (or registered domain). overrides: {"app:<app>", "site:<site>",
    "app:<app>@<dept>": category} chosen by the user - the department's own choice wins."""
    app = app_of_name(name)
    cat = APP_INFO[app][0] if app else None
    if app is None:
        low = (org or "").lower()
        for words, nm, c in ORG_HINTS:
            if any(w in low for w in words):
                app, cat = nm, c
                break
    if app is None and port in PORT_RULES:
        app, cat = PORT_RULES[port]
    if app is None:
        app = site_of(name) or (org[:40] if org else "Other / unknown")
        cat = NEUTRAL
    ov = overrides or {}
    site = site_of(name)
    cat = (ov.get(f"app:{app}@{dept}") if dept else None) or ov.get("site:" + site) or ov.get("app:" + app) or cat
    return app, cat


def _private(ip):
    try:
        return ipaddress.IPv4Address(ip).is_private
    except Exception:
        return False


# ==========================================================================
class UsageStore:
    def __init__(self, path, settings_path=None):
        self.path = path
        self.settings_path = settings_path or os.path.join(os.path.dirname(path), "usage-settings.json")
        self.lock = threading.Lock()
        self.ip_name = collections.OrderedDict()   # internet IP -> {DNS name: times seen} (router cache / DNS firewall)
        self.dev_ip_name = collections.OrderedDict()  # (LAN IP, internet IP) -> name that device looked up
        self.devmap = {}                           # LAN IP -> (key, name)  key = MAC when known
        self.cur = collections.defaultdict(lambda: [0, 0, 0])   # (day, hour, dev, app, site, cat) -> up, down, flows
        self.visits = collections.Counter()        # (day, hour, dev, site) -> DNS look-ups
        self.slot_bytes = collections.Counter()    # (dev, app, cat) -> bytes in the current 5-min slot
        self.slot = None
        self.active = collections.Counter()        # (day, hour, dev, app, cat) -> active minutes
        self.overrides = {}
        self._load_settings()
        self._init_db()
        self.last_flush = time.time()

    # ---- settings (the user's own categories)
    def _load_settings(self):
        try:
            with open(self.settings_path, encoding="utf-8") as f:
                self.overrides = json.load(f).get("overrides", {})
        except (OSError, ValueError):
            self.overrides = {}

    def set_category(self, kind, value, cat, dept=""):
        """kind 'app' or 'site'; cat work / neutral / personal, or None to go back to the built-in rule.
        dept: only for that department's devices (e.g. WhatsApp is work for Sales)."""
        key = f"{kind}:{value}" + (f"@{dept}" if dept and kind == "app" else "")
        self.flush(force=True)  # traffic still in memory must follow the new choice too
        with self.lock:
            if cat:
                self.overrides[key] = cat
            else:
                self.overrides.pop(key, None)
            data = {"overrides": self.overrides}
        try:
            os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)
            with open(self.settings_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1)
        except OSError:
            pass
        # the history follows the user's choice too
        with self._db() as db:
            col = "app" if kind == "app" else "site"
            if dept and kind == "app":
                new = cat or self.category_of(value)
                sub = "dev IN (SELECT dev FROM devices WHERE dept=?)"
                db.execute(f"UPDATE usage SET cat=? WHERE app=? AND {sub}", (new, value, dept))
                db.execute(f"UPDATE active SET cat=? WHERE app=? AND {sub}", (new, value, dept))
                return
            new = cat or self._rule_cat(kind, value)
            depts = {k.split("@", 1)[1] for k in self.overrides if k.startswith(f"app:{value}@")} if kind == "app" else set()
            keep = (" AND dev NOT IN (SELECT dev FROM devices WHERE dept IN (%s))" % ",".join("?" * len(depts))
                    if depts else "")
            db.execute(f"UPDATE usage SET cat=? WHERE {col}=?" + keep, (new, value, *depts))
            if kind == "app":
                db.execute("UPDATE active SET cat=? WHERE app=?" + keep, (new, value, *depts))

    def _rule_cat(self, kind, value):
        if kind == "app":
            return APP_INFO.get(value, (NEUTRAL, ""))[0]
        return classify(value)[1]

    def category_of(self, app, dept=""):
        """The category in force for an app (department choice, then the user's choice, then the built-in one)."""
        ov = self.overrides
        return ((ov.get(f"app:{app}@{dept}") if dept else None) or ov.get("app:" + app)
                or APP_INFO.get(app, (NEUTRAL, ""))[0])

    def app_list(self):
        """Every known app with its group, built-in category, the user's choice and per-department choices."""
        out = []
        depts = collections.defaultdict(dict)
        for k, v in self.overrides.items():
            if k.startswith("app:") and "@" in k:
                a, d = k[4:].split("@", 1)
                depts[a][d] = v
        for app, cat, grp, doms in CATALOG:
            out.append({"app": app, "group": grp, "builtin": cat, "chosen": self.overrides.get("app:" + app),
                        "depts": dict(depts.get(app, {})), "domains": doms})
        return out

    # ---- database
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        return db

    def _init_db(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS usage (day TEXT, hour INT, dev TEXT, app TEXT, site TEXT, cat TEXT,"
                       " up INT, down INT, flows INT, PRIMARY KEY (day, hour, dev, app, site))")
            db.execute("CREATE TABLE IF NOT EXISTS active (day TEXT, hour INT, dev TEXT, app TEXT, cat TEXT,"
                       " minutes INT, PRIMARY KEY (day, hour, dev, app))")
            db.execute("CREATE TABLE IF NOT EXISTS visits (day TEXT, hour INT, dev TEXT, site TEXT, n INT,"
                       " PRIMARY KEY (day, hour, dev, site))")
            db.execute("CREATE TABLE IF NOT EXISTS devices (dev TEXT PRIMARY KEY, name TEXT, ip TEXT, dept TEXT,"
                       " last TEXT)")
            # per-device views (Usage tab, a person's day) stay fast with months of history
            for t in ("usage", "active", "visits"):
                db.execute(f"CREATE INDEX IF NOT EXISTS {t}_dev_day ON {t} (dev, day)")
            try:
                db.execute("PRAGMA journal_mode=WAL")  # the UI reads while the monitor writes
            except sqlite3.DatabaseError:
                pass

    # ---- inputs
    def set_devices(self, devices, tags=None):
        """devices from the scan: maps each LAN IP to its MAC (history stays with the device when its IP changes)."""
        tags = tags or {}
        m, rows = {}, []
        for d in devices or []:
            mac, ip = d.get("mac") or "", d.get("ip") or ""
            t = tags.get(mac, {}) if mac else {}
            name = t.get("name") or d.get("name") or ip
            key = mac or ip
            for x in (d.get("ips") or [ip]):
                if x and d.get("online", True):
                    m[x] = (key, name, t.get("dept", ""))
            if key:
                rows.append((key, name, ip, t.get("dept", ""), time.strftime("%Y-%m-%d %H:%M")))
        with self.lock:
            self.devmap = m
        if rows:
            with self._db() as db:
                db.executemany("INSERT INTO devices VALUES (?,?,?,?,?) ON CONFLICT(dev) DO UPDATE SET "
                               "name=excluded.name, ip=excluded.ip, dept=excluded.dept, last=excluded.last", rows)

    def learn_names(self, pairs, client=None):
        """[(internet_ip, dns_name)] from the router's DNS cache (all devices) or the website firewall (client =
        the device that asked). One address can serve several apps (Google and Meta share front ends), so every
        name seen for an address is kept, and a device's own look-up wins for that device."""
        with self.lock:
            for ip, name in pairs:
                if not ip or not name or _private(ip):
                    continue
                name = name.lower().strip(".")
                names = self.ip_name.get(ip)
                if not isinstance(names, dict):
                    names = {}
                names[name] = names.get(name, 0) + 1
                if len(names) > 12:
                    del names[min(names, key=names.get)]
                self.ip_name[ip] = names
                self.ip_name.move_to_end(ip)
                if client:
                    self.dev_ip_name[(client, ip)] = name
                    self.dev_ip_name.move_to_end((client, ip))
            while len(self.ip_name) > 200_000:
                self.ip_name.popitem(last=False)
            while len(self.dev_ip_name) > 300_000:
                self.dev_ip_name.popitem(last=False)

    def app_for(self, lan, remote):
        """App name for the live monitor, when a DNS name is known for this address; otherwise None."""
        with self.lock:
            name, shared = self.name_for(lan, remote)
        app = app_of_name(name) if name else None
        if app and shared and app in SHARED_FRONTENDS:
            return SHARED_FRONTENDS[app]
        return app

    def name_for(self, lan, remote):
        """(DNS name, shared): the name this device looked up for this address, else the address's most
        common name; shared = the address serves several apps and this device's own look-up is not known."""
        own = self.dev_ip_name.get((lan, remote))
        if own:
            return own, False
        names = self.ip_name.get(remote) or {}
        if not names:
            return "", False
        best = max(names, key=names.get)
        apps = {app_of_name(n) or site_of(n) for n in names}
        return best, len(apps) > 1

    def dns_seen(self, client, name, ips=(), now=None):
        """One DNS look-up by a device (website firewall): counts a visit and learns the answer's addresses."""
        now = now or time.time()
        site = site_of(name)
        if ips:
            self.learn_names([(ip, name) for ip in ips], client)
        if not site or not _private(client):
            return
        tm = time.localtime(now)
        with self.lock:
            dev = self.devmap.get(client, (client, client))[0]
            self.visits[(time.strftime("%Y-%m-%d", tm), tm.tm_hour, dev, site)] += 1

    def add_flow(self, lan, remote, port, proto, nbytes, up, org="", now=None):
        """One NetFlow record already matched to a LAN device (called by the live monitor)."""
        if nbytes <= 0:
            return
        now = now or time.time()
        tm = time.localtime(now)
        day, hour = time.strftime("%Y-%m-%d", tm), tm.tm_hour
        with self.lock:
            name, shared = self.name_for(lan, remote)
            info = self.devmap.get(lan) or (lan, lan, "")
            dev, dept = info[0], (info[2] if len(info) > 2 else "")
            ov = self.overrides
        from_ptr = False
        if not name:  # no DNS name for this address: the server's own name still says a lot (whatsapp-cdn...)
            ptr = ptr_of(org)
            if ptr and app_of_name(ptr):
                name, from_ptr = ptr, True
        site = pretty_site(name if from_ptr else org) if (from_ptr or not name) else site_of(name)
        app, cat = classify(name, org, port, ov, dept)
        if app == name and site:
            app = site
        if shared and app in SHARED_FRONTENDS:
            # a page / login address shared by several Google or Meta apps: do not guess the app
            app = SHARED_FRONTENDS[app]
            cat = (ov.get(f"app:{app}@{dept}") if dept else None) or ov.get("app:" + app) or NEUTRAL
        with self.lock:
            r = self.cur[(day, hour, dev, app, (site or "")[:60], cat)]
            r[0 if up else 1] += nbytes
            r[2] += 1
            slot = int(now // SLOT)
            if self.slot is not None and slot != self.slot:
                self._close_slot()
            self.slot = slot
            self.slot_bytes[(dev, app, cat, day, hour)] += nbytes

    def _close_slot(self):
        for (dev, app, cat, day, hour), b in self.slot_bytes.items():
            if b >= ACTIVE_BYTES:
                self.active[(day, hour, dev, app, cat)] += SLOT // 60
        self.slot_bytes.clear()

    def flush(self, force=False):
        if not force and time.time() - self.last_flush < 60:
            return
        self.last_flush = time.time()
        with self.lock:
            if force:
                self._close_slot()
            cur, self.cur = self.cur, collections.defaultdict(lambda: [0, 0, 0])
            act, self.active = self.active, collections.Counter()
            vis, self.visits = self.visits, collections.Counter()
        if not (cur or act or vis):
            return
        with self._db() as db:
            db.executemany("INSERT INTO usage VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(day, hour, dev, app, site) DO "
                           "UPDATE SET up=up+excluded.up, down=down+excluded.down, flows=flows+excluded.flows, "
                           "cat=excluded.cat", [k + tuple(v) for k, v in cur.items()])
            db.executemany("INSERT INTO active VALUES (?,?,?,?,?,?) ON CONFLICT(day, hour, dev, app) DO UPDATE SET "
                           "minutes=minutes+excluded.minutes", [k + (v,) for k, v in act.items()])
            db.executemany("INSERT INTO visits VALUES (?,?,?,?,?) ON CONFLICT(day, hour, dev, site) DO UPDATE SET "
                           "n=n+excluded.n", [k + (v,) for k, v in vis.items()])
            cut = (dt.date.today() - dt.timedelta(days=KEEP_DAYS)).isoformat()
            for t in ("usage", "active", "visits"):
                db.execute(f"DELETE FROM {t} WHERE day < ?", (cut,))

    # ---- reading
    def _rows(self, sql, args=()):
        self.flush(force=True)
        with self._db() as db:
            return db.execute(sql, args).fetchall()

    def names(self):
        return {r[0]: {"name": r[1], "ip": r[2], "dept": r[3]} for r in self._rows("SELECT * FROM devices")}

    def summary(self, days=1, dev=None, end=None):
        """Everything the Usage tab and the dashboard show, for the last `days` days (1 = today)."""
        end = end or dt.date.today()
        start = (end - dt.timedelta(days=days - 1)).isoformat()
        stop = end.isoformat()
        w, a = "day BETWEEN ? AND ?", [start, stop]
        if dev:
            w += " AND dev=?"
            a.append(dev)
        names = self.names()
        cat = {r[0]: r[1] + r[2] for r in self._rows(f"SELECT cat, SUM(up), SUM(down) FROM usage WHERE {w} GROUP BY cat", a)}
        apps = [{"app": r[0], "cat": r[1], "bytes": r[2], "devices": r[3], "group": group_of(r[0])} for r in self._rows(
            f"SELECT app, cat, SUM(up+down) b, COUNT(DISTINCT dev) FROM usage WHERE {w} GROUP BY app, cat "
            "ORDER BY b DESC LIMIT 60", a)]
        mins = {(r[0], r[1]): r[2] for r in self._rows(
            f"SELECT app, cat, SUM(minutes) FROM active WHERE {w} GROUP BY app, cat", a)}
        for x in apps:
            x["minutes"] = mins.get((x["app"], x["cat"]), 0)
        sites = [{"site": r[0], "app": r[1], "cat": r[2], "bytes": r[3], "devices": r[4]} for r in self._rows(
            f"SELECT site, app, cat, SUM(up+down) b, COUNT(DISTINCT dev) FROM usage WHERE {w} AND site != '' "
            "GROUP BY site ORDER BY b DESC LIMIT 60", a)]
        vis = {r[0]: r[1] for r in self._rows(f"SELECT site, SUM(n) FROM visits WHERE {w} GROUP BY site", a)}
        for x in sites:
            x["visits"] = vis.pop(x["site"], 0)
        for s, n in sorted(vis.items(), key=lambda kv: -kv[1])[:30]:  # visited, but no NetFlow bytes for it
            app, c = classify(s, overrides=self.overrides)
            sites.append({"site": s, "app": app, "cat": c, "bytes": 0, "devices": 0, "visits": n})
        devs = {}
        for d, b, u in self._rows(f"SELECT dev, SUM(up+down), SUM(up) FROM usage WHERE {w} GROUP BY dev", a):
            n = names.get(d, {})
            devs[d] = {"dev": d, "name": n.get("name") or d, "ip": n.get("ip", ""), "dept": n.get("dept", ""),
                       "bytes": b, "up": u, "work": 0, "neutral": 0, "personal": 0, "top": ""}
        for d, c, m in self._rows(f"SELECT dev, cat, SUM(minutes) FROM active WHERE {w} GROUP BY dev, cat", a):
            if d in devs:
                devs[d][c] = m
        for d, app, b in self._rows(f"SELECT dev, app, SUM(up+down) b FROM usage WHERE {w} AND cat='personal' "
                                    "GROUP BY dev, app ORDER BY b DESC", a):
            if d in devs and not devs[d]["top"]:
                devs[d]["top"] = app
        for x in devs.values():
            x["score"] = productivity(x["work"], x["personal"])
        hours = collections.defaultdict(lambda: {WORK: 0, NEUTRAL: 0, PERSONAL: 0})
        for day, hour, c, b in self._rows(f"SELECT day, hour, cat, SUM(up+down) FROM usage WHERE {w} "
                                          "GROUP BY day, hour, cat", a):
            hours[f"{day} {hour:02d}"][c] += b
        return {"start": start, "end": stop, "days": days, "dev": dev, "cats": cat, "apps": apps, "sites": sites,
                "devices": sorted(devs.values(), key=lambda x: -x["bytes"]),
                "hours": [{"t": k, **v} for k, v in sorted(hours.items())]}

    # ---- learning: what is normal here, and what to do about the rest
    def insights(self, days=21, today=None):
        today = today or dt.date.today()
        start = (today - dt.timedelta(days=days)).isoformat()
        rows = self._rows("SELECT day, hour, app, cat, dev, up+down FROM usage WHERE day >= ?", (start,))
        out = []
        if not rows:
            return [{"sev": "info", "title": "Still learning",
                     "text": "No usage recorded yet. It needs NetFlow from the router (Setup > Router commands) and "
                             "the Live monitor running. Names of websites come from the router's DNS cache (router "
                             "login in Setup) or the website firewall.", "action": ""}]
        names = self.names()
        total_by_dayhour = collections.Counter()
        app_by_hour = collections.defaultdict(collections.Counter)
        app_days_at_peak = collections.defaultdict(set)
        cat_total = collections.Counter()
        dev_day = collections.defaultdict(collections.Counter)
        dev_app = collections.defaultdict(collections.Counter)
        app_cat = {}
        for day, hour, app, cat, dev, b in rows:
            total_by_dayhour[(day, hour)] += b
            app_by_hour[hour][app] += b
            cat_total[cat] += b
            dev_day[dev][day] += b
            dev_app[dev][app] += b
            app_cat[app] = cat
        days_seen = sorted({d for d, _ in total_by_dayhour})
        n_days = max(1, len(days_seen))
        # busy hours: average traffic per hour of day
        by_hour = collections.Counter()
        for (day, hour), b in total_by_dayhour.items():
            by_hour[hour] += b / n_days
        if by_hour:
            peak = sorted(by_hour, key=lambda h: -by_hour[h])[:3]
            dha = collections.defaultdict(collections.Counter)
            for day, hour, app, cat, dev, b in rows:
                if hour in peak:
                    dha[(day, hour)][app] += b
            for (day, hour), c in dha.items():
                for a, _ in c.most_common(3):
                    app_days_at_peak[a].add(day)
            ph = ", ".join(f"{h:02d}:00" for h in sorted(peak))
            tot_peak = sum(app_by_hour[h][a] for h in peak for a in app_by_hour[h]) or 1
            habit = [(a, len(ds)) for a, ds in app_days_at_peak.items() if len(ds) >= max(2, n_days // 2)]
            habit.sort(key=lambda x: -sum(app_by_hour[h][x[0]] for h in peak))
            if habit:
                parts = []
                for a, nd in habit[:4]:
                    share = 100 * sum(app_by_hour[h][a] for h in peak) / tot_peak
                    parts.append(f"{a} {share:.0f}% ({nd} of {n_days} days)")
                personal = [a for a, _ in habit[:4] if app_cat.get(a) == PERSONAL]
                out.append({"sev": "warning" if personal else "info", "title": f"Busiest hours: {ph}",
                            "text": "Every day the line is fullest at these hours. Regularly at the top then: "
                                    + "; ".join(parts) + ".",
                            "action": (f"{', '.join(personal)} fill the line at the busiest time: block them in "
                                       "working hours (Tools > Website firewall) or limit their speed, so work apps "
                                       "stay fast." if personal else
                                       "Mostly work traffic at the busy hours - if it feels slow then, the internet "
                                       "line itself is too small.")})
        total = sum(cat_total.values()) or 1
        share_p = 100 * cat_total[PERSONAL] / total
        if share_p >= 15:
            top_p = collections.Counter()
            for hour in app_by_hour:
                for a, b in app_by_hour[hour].items():
                    if app_cat.get(a) == PERSONAL:
                        top_p[a] += b
            out.append({"sev": "warning" if share_p >= 30 else "info",
                        "title": f"{share_p:.0f}% of all internet traffic is not work",
                        "text": "Largest: " + ", ".join(f"{a} {fmt_bytes(b)}" for a, b in top_p.most_common(4)) + ".",
                        "action": "Block or limit these categories in working hours (Tools > Website firewall: "
                                  "Video, Social media, Games), or mark them Productive if the office needs them."})
        # devices far above their own normal
        last = days_seen[-1] if days_seen else today.isoformat()
        for dev, per_day in dev_day.items():
            hist = [b for d, b in per_day.items() if d != last]
            if len(hist) >= 3 and per_day.get(last, 0) > 3 * max(statistics.mean(hist), 200e6 / 3):
                nm = names.get(dev, {}).get("name") or dev
                top = dev_app[dev].most_common(1)[0][0] if dev_app[dev] else "?"
                out.append({"sev": "warning", "title": f"{nm} used {fmt_bytes(per_day[last])} on {last}",
                            "text": f"About {per_day[last] / max(statistics.mean(hist), 1):.0f} times its usual "
                                    f"daily use. Mostly: {top}.",
                            "action": "Check what runs on it (Analyse in the Devices tab). A backup, update or video "
                                      "download all day - limit its speed (Commands > Limit the speed of one device)."})
        # one device eats a large part of the line
        dev_total = collections.Counter({d: sum(v.values()) for d, v in dev_day.items()})
        if dev_total and len(dev_total) >= 3:
            d, b = dev_total.most_common(1)[0]
            if b / total >= 0.3:
                nm = names.get(d, {}).get("name") or d
                out.append({"sev": "warning", "title": f"{nm} alone uses {100 * b / total:.0f}% of the internet",
                            "text": "Top apps: " + ", ".join(f"{a} {fmt_bytes(x)}" for a, x in
                                                             dev_app[d].most_common(3)) + ".",
                            "action": "Give it a speed limit, or schedule its big jobs (backup, CCTV upload, "
                                      "updates) after office hours."})
        # updates / backups during office hours
        upd = [a for a in set().union(*[set(c) for c in app_by_hour.values()]) if group_of(a) == "Updates & drivers"]
        for hour in range(24):  # all updates and driver downloads together
            app_by_hour[hour]["Updates & drivers (all)"] = sum(app_by_hour[hour][a] for a in upd)
        for a in ("Updates & drivers (all)", "Dropbox", "OneDrive / SharePoint", "Apple / iCloud", "CCTV cloud"):
            work_h = sum(app_by_hour[h][a] for h in range(10, 18))
            if work_h > 2e9 * max(1, n_days / 7):
                out.append({"sev": "info", "title": f"{a}: {fmt_bytes(work_h)} during office hours",
                            "text": "Large downloads / uploads between 10:00 and 18:00 slow everybody else.",
                            "action": "Schedule it for the night (Windows: Active hours and Delivery Optimization "
                                      "limits; Dell / Lenovo / HP update tools: set to notify only; backups and CCTV "
                                      "cloud: night schedule)."})
        if n_days < 7:
            out.append({"sev": "info", "title": f"Learning: {n_days} day(s) recorded",
                        "text": "Patterns and 'unusual' warnings get reliable after a week of data.", "action": ""})
        return out


def productivity(work_min, personal_min):
    """0-100: share of non-neutral active time spent on work apps (None when there is no such time)."""
    t = (work_min or 0) + (personal_min or 0)
    return None if t <= 0 else round(100 * work_min / t)


def fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u in ("B", "KB") else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


# ==========================================================================
# interactive dashboard (one HTML file, no internet needed to open it)
# ==========================================================================
def dashboard_data(store, days=30, hourly_days=14):
    end = dt.date.today()
    start = (end - dt.timedelta(days=days - 1)).isoformat()
    hstart = (end - dt.timedelta(days=hourly_days - 1)).isoformat()
    per = collections.defaultdict(list)
    for day, dev, app, cat, b in store._rows(
            "SELECT day, dev, app, cat, SUM(up+down) FROM usage WHERE day >= ? GROUP BY day, dev, app", (start,)):
        per[(day, dev)].append((b, app, cat))
    apps = []
    for (day, dev), lst in per.items():
        lst.sort(reverse=True)
        for b, app, cat in lst[:25]:
            apps.append([day, dev, app, cat, b])
        rest = collections.Counter()
        for b, app, cat in lst[25:]:
            rest[cat] += b
        for cat, b in rest.items():
            apps.append([day, dev, "Other", cat, b])
    hours = [list(r) for r in store._rows(
        "SELECT day, hour, dev, cat, SUM(up+down) FROM usage WHERE day >= ? GROUP BY day, hour, dev, cat", (hstart,))]
    act = [list(r) for r in store._rows(
        "SELECT day, dev, cat, SUM(minutes) FROM active WHERE day >= ? GROUP BY day, dev, cat", (start,))]
    sites = [list(r) for r in store._rows(
        "SELECT day, dev, site, app, cat, SUM(up+down) b FROM usage WHERE day >= ? AND site != '' "
        "GROUP BY day, dev, site", (start,))]
    visits = [list(r) for r in store._rows(
        "SELECT day, dev, site, SUM(n) FROM visits WHERE day >= ? GROUP BY day, dev, site", (start,))]
    return {"generated": time.strftime("%Y-%m-%d %H:%M"), "start": start, "end": end.isoformat(),
            "hourly_from": hstart, "devices": store.names(), "apps": apps, "hours": hours, "act": act,
            "sites": sites, "visits": visits, "insights": store.insights(),
            "labels": CAT_LABEL}


def dashboard_html(store, days=30):
    data = json.dumps(dashboard_data(store, days), separators=(",", ":")).replace("</", "<\\/")
    return DASHBOARD.replace("/*DATA*/null", data)


DASHBOARD = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Doctor - internet usage</title>
<style>
.viz-root{color-scheme:light;--surface-0:#f3f3f1;--surface-1:#fcfcfb;--line:#e4e3df;--grid:#ecebe7;
 --text-primary:#0b0b0b;--text-secondary:#52514e;--text-muted:#7a7974;
 --work:#2a78d6;--personal:#eb6834;--neutral:#1baf7a;--warn:#b35c00;--warnbg:#fff4e5;--info:#2a78d6;
 --seq1:#cde2fb;--seq7:#0d366b;--focus:#2a78d6}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;
 --surface-0:#111110;--surface-1:#1a1a19;--line:#2e2e2c;--grid:#262624;--text-primary:#f0efec;--text-secondary:#c3c2b7;
 --text-muted:#8f8e88;--work:#3987e5;--personal:#d95926;--neutral:#199e70;--warn:#f0a040;--warnbg:#2b2213;
 --seq1:#1b2a3d;--seq7:#86b6ef}}
:root[data-theme="dark"] .viz-root{color-scheme:dark;--surface-0:#111110;--surface-1:#1a1a19;--line:#2e2e2c;--grid:#262624;
 --text-primary:#f0efec;--text-secondary:#c3c2b7;--text-muted:#8f8e88;--work:#3987e5;--personal:#d95926;--neutral:#199e70;
 --warn:#f0a040;--warnbg:#2b2213;--seq1:#1b2a3d;--seq7:#86b6ef}
*{box-sizing:border-box}body{margin:0}
.viz-root{background:var(--surface-0);color:var(--text-primary);font:14px/1.45 "Segoe UI",system-ui,sans-serif;min-height:100vh;padding:20px 24px 40px}
h1{font-size:20px;margin:0 0 2px}h2{font-size:15px;margin:0 0 10px}.sub{color:var(--text-secondary);font-size:13px}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:14px 0 16px}
.filters select,.seg button{font:inherit;color:var(--text-primary);background:var(--surface-1);border:1px solid var(--line);border-radius:8px;padding:6px 10px}
.seg{display:inline-flex}.seg button{border-radius:0;margin-left:-1px;cursor:pointer}.seg button:first-child{border-radius:8px 0 0 8px}
.seg button:last-child{border-radius:0 8px 8px 0}.seg button[aria-pressed=true]{background:var(--text-primary);color:var(--surface-1)}
button:focus-visible,select:focus-visible,tr:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
.card{background:var(--surface-1);border:1px solid var(--line);border-radius:12px;padding:14px 16px;min-width:0}
.c3{grid-column:span 3}.c4{grid-column:span 4}.c5{grid-column:span 5}.c6{grid-column:span 6}.c7{grid-column:span 7}.c8{grid-column:span 8}.c12{grid-column:span 12}
@media(max-width:1000px){.c3{grid-column:span 6}.c4,.c5,.c6,.c7,.c8{grid-column:span 12}}
.kpi .v{font-size:26px;font-weight:600;font-variant-numeric:tabular-nums}.kpi .l{color:var(--text-secondary);font-size:12px}
.legend{display:flex;gap:14px;font-size:12px;color:var(--text-secondary);margin-bottom:6px}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
svg{display:block;width:100%;overflow:visible}svg text{fill:var(--text-secondary);font-size:11px}
.bar:hover,.cell:hover{opacity:.8}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--text-muted);font-weight:500;padding:6px 6px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap}
td{padding:6px 6px;border-bottom:1px solid var(--grid);font-variant-numeric:tabular-nums}tbody tr{cursor:pointer}tbody tr:hover{background:var(--grid)}
td.n{text-align:right}.score{display:inline-block;height:8px;border-radius:4px;background:var(--work);vertical-align:middle}
.tag{font-size:11px;padding:1px 7px;border-radius:9px;border:1px solid var(--line);color:var(--text-secondary);white-space:nowrap}
.ins{border-left:3px solid var(--info);padding:6px 10px;margin:0 0 10px;background:var(--surface-0);border-radius:0 8px 8px 0}
.ins.warning{border-color:var(--warn);background:var(--warnbg)}.ins b{display:block}.ins .a{color:var(--text-secondary);margin-top:3px}
#tip{position:fixed;pointer-events:none;background:var(--surface-1);color:var(--text-primary);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font-size:12px;box-shadow:0 4px 14px rgba(0,0,0,.15);display:none;z-index:9;max-width:320px}
.empty{color:var(--text-muted);padding:20px 0}.scroll{max-height:420px;overflow:auto}
</style></head><body><div class="viz-root">
<h1>Internet usage and productivity</h1>
<div class="sub" id="sub"></div>
<div class="filters">
 <span class="seg" id="period"><button data-d="1">Today</button><button data-d="7">7 days</button><button data-d="30">30 days</button></span>
 <select id="dept" aria-label="Department"></select>
 <select id="dev" aria-label="Device"></select>
 <span class="sub" id="note"></span>
</div>
<div class="grid">
 <div class="card kpi c3"><div class="l">Internet traffic</div><div class="v" id="k1"></div><div class="l" id="k1s"></div></div>
 <div class="card kpi c3"><div class="l">Productive share of active time</div><div class="v" id="k2"></div><div class="l" id="k2s"></div></div>
 <div class="card kpi c3"><div class="l">Unproductive time</div><div class="v" id="k3"></div><div class="l" id="k3s"></div></div>
 <div class="card kpi c3"><div class="l">Busiest hour</div><div class="v" id="k4"></div><div class="l" id="k4s"></div></div>
 <div class="card c8"><h2 id="t_time">Traffic over time</h2><div class="legend" id="lg1"></div><div id="ch_time"></div></div>
 <div class="card c4"><h2>What the advisor learned</h2><div id="ins" class="scroll"></div></div>
 <div class="card c6"><h2>Apps by traffic</h2><div class="legend" id="lg2"></div><div id="ch_apps"></div></div>
 <div class="card c6"><h2>When the line is busy (average per weekday and hour)</h2><div id="ch_heat"></div></div>
 <div class="card c7"><h2>Devices and users <span class="sub">- click a row to see only that device</span></h2><div class="scroll"><table id="t_dev"></table></div></div>
 <div class="card c5"><h2>Websites</h2><div class="scroll"><table id="t_sites"></table></div></div>
</div>
<div id="tip" role="tooltip"></div>
<p class="sub" style="margin-top:18px">Active time = 5-minute periods in which a device moved at least 150 KB for an app. Productive share = productive time / (productive + unproductive). Categories can be changed in Network Doctor &gt; Usage. Made by Network Doctor; the data stays on this PC.</p>
</div>
<script>
const D=/*DATA*/null;
const CATS=["work","neutral","personal"],LBL=D.labels,css=n=>getComputedStyle(document.querySelector('.viz-root')).getPropertyValue(n).trim();
const col=c=>css('--'+c);const st={days:7,dev:"",dept:""};
const fmtB=n=>{n=+n||0;const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<4){n/=1024;i++}return (i<2?n.toFixed(0):n.toFixed(1))+" "+u[i]};
const fmtM=m=>{m=Math.round(m||0);return m<60?m+" min":Math.floor(m/60)+" h "+String(m%60).padStart(2,"0")};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const tip=document.getElementById("tip");
function showTip(e,h){tip.innerHTML=h;tip.style.display="block";const w=tip.offsetWidth,x=Math.min(e.clientX+14,innerWidth-w-8);tip.style.left=x+"px";tip.style.top=(e.clientY+14)+"px"}
function hideTip(){tip.style.display="none"}
function dayAdd(s,n){const d=new Date(s+"T12:00:00");d.setDate(d.getDate()+n);return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0")}
const devName=k=>(D.devices[k]&&D.devices[k].name)||k,devDept=k=>(D.devices[k]&&D.devices[k].dept)||"";
function keep(day,dev){if(day<dayAdd(D.end,1-st.days))return false;if(st.dev&&dev!==st.dev)return false;if(st.dept&&devDept(dev)!==st.dept)return false;return true}
function legend(id){document.getElementById(id).innerHTML=CATS.map(c=>`<span><i class="sw" style="background:${col(c)}"></i>${LBL[c]}</span>`).join("")}
function svgEl(w,h,inner){return `<svg viewBox="0 0 ${w} ${h}" role="img">${inner}</svg>`}
function bind(root){root.querySelectorAll("[data-tip]").forEach(el=>{el.addEventListener("mousemove",e=>showTip(e,el.dataset.tip));el.addEventListener("mouseleave",hideTip)})}
function niceMax(v){if(v<=0)return 1;const p=Math.pow(1024,Math.floor(Math.log(v)/Math.log(1024)));const x=v/p;const s=[1,2,4,5,8,10,20,25,50,100,200,250,500,1000].find(s=>s>=x)||x;return s*p}

function drawTime(){
 const byH=st.days===1,box=document.getElementById("ch_time"),W=760,H=240,L=58,B=26,T=8;
 const buckets=new Map();
 if(byH){for(let h=0;h<24;h++)buckets.set(h,{work:0,neutral:0,personal:0});
  D.hours.forEach(([d,h,dv,c,b])=>{if(d===D.end&&keep(d,dv))buckets.get(h)[c]+=b})}
 else{for(let i=st.days-1;i>=0;i--)buckets.set(dayAdd(D.end,-i),{work:0,neutral:0,personal:0});
  D.apps.forEach(([d,dv,a,c,b])=>{if(buckets.has(d)&&keep(d,dv))buckets.get(d)[c]+=b})}
 document.getElementById("t_time").textContent=byH?"Traffic per hour today":"Traffic per day";
 const keys=[...buckets.keys()],tot=keys.map(k=>CATS.reduce((s,c)=>s+buckets.get(k)[c],0)),mx=niceMax(Math.max(...tot,1));
 if(!tot.some(x=>x>0)){box.innerHTML='<div class="empty">No traffic recorded for this selection yet.</div>';return}
 const cw=(W-L)/keys.length,bw=Math.max(3,Math.min(34,cw*0.7));let g="";
 for(let i=0;i<=4;i++){const y=T+(H-B-T)*(1-i/4);g+=`<line x1="${L}" x2="${W}" y1="${y}" y2="${y}" stroke="${css('--grid')}"/><text x="${L-6}" y="${y+4}" text-anchor="end">${fmtB(mx*i/4)}</text>`}
 keys.forEach((k,i)=>{const x=L+i*cw+(cw-bw)/2;let y=H-B;const v=buckets.get(k);
  const lab=byH?String(k).padStart(2,"0")+":00":k;
  const tipH=`<b>${esc(lab)}</b><br>`+CATS.map(c=>`<i class="sw" style="background:${col(c)}"></i>${LBL[c]}: ${fmtB(v[c])}`).join("<br>")+`<br>Total ${fmtB(tot[i])}`;
  const segs=CATS.filter(c=>v[c]>0);
  segs.forEach((c,j)=>{const h=(H-B-T)*v[c]/mx;if(h<0.5)return;const top=j===segs.length-1,gap=j>0?2:0;
   const hh=Math.max(0.5,h-gap);y-=h;
   g+=top?`<path class="bar" d="M${x},${y+gap+hh} v${-(hh-4)} a4,4 0 0 1 4,-4 h${bw-8} a4,4 0 0 1 4,4 v${hh-4} z" fill="${col(c)}"/>`
        :`<rect class="bar" x="${x}" y="${y+gap}" width="${bw}" height="${hh}" fill="${col(c)}"/>`});
  g+=`<rect x="${L+i*cw}" y="${T}" width="${cw}" height="${H-B-T}" fill="transparent" data-tip="${esc(tipH)}"/>`;
  const every=byH?3:Math.ceil(keys.length/10);if(i%every===0)g+=`<text x="${x+bw/2}" y="${H-8}" text-anchor="middle">${byH?String(k).padStart(2,"0"):k.slice(5)}</text>`});
 box.innerHTML=svgEl(W,H,g);bind(box)}

function drawApps(){
 const m=new Map();D.apps.forEach(([d,dv,a,c,b])=>{if(keep(d,dv)){const r=m.get(a)||{b:0,c};r.b+=b;m.set(a,r)}});
 const rows=[...m.entries()].sort((x,y)=>y[1].b-x[1].b).slice(0,12),box=document.getElementById("ch_apps");
 if(!rows.length){box.innerHTML='<div class="empty">No apps recorded for this selection yet.</div>';return}
 const W=560,rh=24,L=170,H=rows.length*rh+4,mx=rows[0][1].b;let g="";
 rows.forEach(([a,r],i)=>{const y=i*rh+2,w=Math.max(2,(W-L-80)*r.b/mx);
  g+=`<text x="${L-8}" y="${y+15}" text-anchor="end" style="fill:${css('--text-primary')}">${esc(a.length>26?a.slice(0,25)+"…":a)}</text>`;
  g+=`<path class="bar" d="M${L},${y+4} h${w-4} a4,4 0 0 1 4,4 v${rh-16} a4,4 0 0 1 -4,4 h${-(w-4)} z" fill="${col(r.c)}" data-tip="${esc(`<b>${esc(a)}</b><br>${LBL[r.c]}<br>${fmtB(r.b)}`)}"/>`;
  g+=`<text x="${L+w+6}" y="${y+15}">${fmtB(r.b)}</text>`});
 box.innerHTML=svgEl(W,H,g);bind(box)}

function drawHeat(){
 const box=document.getElementById("ch_heat"),days=["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],sum={},cnt={};
 const seen=new Set();D.hours.forEach(([d,h,dv,c,b])=>{if(!keep(d,dv))return;const wd=(new Date(d+"T00:00:00").getDay()+6)%7;sum[wd+"_"+h]=(sum[wd+"_"+h]||0)+b;seen.add(d)});
 seen.forEach(d=>{const wd=(new Date(d+"T00:00:00").getDay()+6)%7;cnt[wd]=(cnt[wd]||0)+1});
 const vals=Object.entries(sum).map(([k,v])=>v/(cnt[k.split("_")[0]]||1)),mx=Math.max(...vals,0);
 if(!mx){box.innerHTML='<div class="empty">Needs hourly data - leave the Live monitor running.</div>';return}
 const W=560,L=34,cs=(W-L)/24,ch=20,H=7*(ch+2)+20;let g="";
 const a=css('--seq1'),b=css('--seq7');const mix=t=>{const p=x=>[1,3,5].map(i=>parseInt(x.slice(i,i+2),16));const A=p(a),Bc=p(b);return "rgb("+A.map((v,i)=>Math.round(v+(Bc[i]-v)*t)).join(",")+")"};
 days.forEach((dn,wd)=>{g+=`<text x="${L-6}" y="${wd*(ch+2)+14}" text-anchor="end">${dn}</text>`;
  for(let h=0;h<24;h++){const v=(sum[wd+"_"+h]||0)/(cnt[wd]||1),t=Math.sqrt(v/mx);
   g+=`<rect class="cell" x="${L+h*cs+1}" y="${wd*(ch+2)}" width="${cs-2}" height="${ch}" rx="3" fill="${v?mix(t):css('--grid')}" data-tip="${esc(`<b>${dn} ${String(h).padStart(2,"0")}:00</b><br>average ${fmtB(v)}`)}"/>`}});
 for(let h=0;h<24;h+=3)g+=`<text x="${L+h*cs+cs/2}" y="${H-4}" text-anchor="middle">${String(h).padStart(2,"0")}</text>`;
 box.innerHTML=svgEl(W,H,g)+`<div class="sub" style="margin-top:6px">Stronger blue = busier hour (last ${Math.min(st.days,14)} days).</div>`;bind(box)}

let devSort="b";
function drawDevices(){
 const m=new Map();const get=k=>{if(!m.has(k))m.set(k,{k,b:0,work:0,neutral:0,personal:0,top:new Map()});return m.get(k)};
 D.apps.forEach(([d,dv,a,c,b])=>{if(!keep(d,dv))return;const r=get(dv);r.b+=b;if(c==="personal")r.top.set(a,(r.top.get(a)||0)+b)});
 D.act.forEach(([d,dv,c,mn])=>{if(keep(d,dv))get(dv)[c]+=mn});
 const rows=[...m.values()].map(r=>{const t=r.work+r.personal;r.score=t?Math.round(100*r.work/t):null;r.tp=[...r.top.entries()].sort((a,b)=>b[1]-a[1])[0];return r});
 rows.sort((a,b)=>devSort==="s"?((a.score??101)-(b.score??101)):devSort==="p"?b.personal-a.personal:b.b-a.b);
 const t=document.getElementById("t_dev");
 t.innerHTML=`<thead><tr><th data-s="n">Device / user</th><th>Dept</th><th data-s="b" class="n">Traffic</th><th class="n">Productive</th><th data-s="p" class="n">Unproductive</th><th data-s="s">Productivity</th><th>Top unproductive app</th></tr></thead><tbody>`+
 rows.map(r=>`<tr tabindex="0" data-k="${esc(r.k)}"><td>${esc(devName(r.k))}<div class="sub">${esc((D.devices[r.k]||{}).ip||r.k)}</div></td><td>${esc(devDept(r.k))}</td><td class="n">${fmtB(r.b)}</td><td class="n">${fmtM(r.work)}</td><td class="n">${fmtM(r.personal)}</td><td>${r.score==null?'<span class="sub">no data</span>':`<span class="score" style="width:${Math.max(2,r.score*0.6)}px"></span> ${r.score}%`}</td><td>${r.tp?esc(r.tp[0])+' <span class="sub">'+fmtB(r.tp[1])+'</span>':""}</td></tr>`).join("")+`</tbody>`;
 t.querySelectorAll("th[data-s]").forEach(th=>th.onclick=()=>{devSort=th.dataset.s;drawDevices()});
 t.querySelectorAll("tbody tr").forEach(tr=>{const go=()=>{st.dev=st.dev===tr.dataset.k?"":tr.dataset.k;document.getElementById("dev").value=st.dev;draw()};tr.onclick=go;tr.onkeydown=e=>{if(e.key==="Enter")go()}});
 if(!rows.length)t.innerHTML='<tr><td class="empty">No devices for this selection yet.</td></tr>'}

function drawSites(){
 const m=new Map();D.sites.forEach(([d,dv,s,a,c,b])=>{if(!keep(d,dv))return;const r=m.get(s)||{s,a,c,b:0,v:0,devs:new Set()};r.b+=b;r.devs.add(dv);m.set(s,r)});
 D.visits.forEach(([d,dv,s,n])=>{if(!keep(d,dv))return;const r=m.get(s)||{s,a:s,c:"neutral",b:0,v:0,devs:new Set()};r.v+=n;r.devs.add(dv);m.set(s,r)});
 const rows=[...m.values()].sort((x,y)=>y.b-x.b||y.v-x.v).slice(0,60),t=document.getElementById("t_sites");
 t.innerHTML=`<thead><tr><th>Website</th><th>Category</th><th class="n">Traffic</th><th class="n">Visits</th><th class="n">Devices</th></tr></thead><tbody>`+
 rows.map(r=>`<tr><td>${esc(r.s)}<div class="sub">${esc(r.a)}</div></td><td><span class="tag"><i class="sw" style="background:${col(r.c)}"></i>${LBL[r.c]}</span></td><td class="n">${fmtB(r.b)}</td><td class="n">${r.v||""}</td><td class="n">${r.devs.size}</td></tr>`).join("")+`</tbody>`;
 if(!rows.length)t.innerHTML='<tr><td class="empty">No website names yet. They come from the router\'s DNS cache (router login in Setup) or the website firewall.</td></tr>'}

function drawKpi(){
 let b=0,w=0,p=0;const h=new Array(24).fill(0);const devs=new Set();
 D.apps.forEach(([d,dv,a,c,x])=>{if(keep(d,dv)){b+=x;devs.add(dv)}});D.act.forEach(([d,dv,c,mn])=>{if(keep(d,dv)){if(c==="work")w+=mn;if(c==="personal")p+=mn}});
 D.hours.forEach(([d,hr,dv,c,x])=>{if(keep(d,dv))h[hr]+=x});const pk=h.indexOf(Math.max(...h));
 const set=(id,v)=>document.getElementById(id).textContent=v;
 set("k1",fmtB(b));set("k1s",devs.size+" device(s)");set("k2",w+p?Math.round(100*w/(w+p))+"%":"–");set("k2s",fmtM(w)+" productive");
 set("k3",fmtM(p));set("k3s",w+p?Math.round(100*p/(w+p))+"% of active time":"");set("k4",Math.max(...h)>0?String(pk).padStart(2,"0")+":00":"–");set("k4s",Math.max(...h)>0?fmtB(h[pk])+" in that hour":"")}

function drawInsights(){document.getElementById("ins").innerHTML=(D.insights||[]).map(i=>`<div class="ins ${esc(i.sev)}"><b>${esc(i.title)}</b>${esc(i.text)}${i.action?`<div class="a">What to do: ${esc(i.action)}</div>`:""}</div>`).join("")||'<div class="empty">Nothing unusual.</div>'}

function fillSelects(){const dv=document.getElementById("dev"),dp=document.getElementById("dept");
 const keys=Object.keys(D.devices).sort((a,b)=>devName(a).localeCompare(devName(b)));
 dv.innerHTML='<option value="">All devices</option>'+keys.map(k=>`<option value="${esc(k)}">${esc(devName(k))}</option>`).join("");
 const depts=[...new Set(keys.map(devDept).filter(Boolean))].sort();dp.innerHTML='<option value="">All departments</option>'+depts.map(d=>`<option>${esc(d)}</option>`).join("");
 dv.onchange=()=>{st.dev=dv.value;draw()};dp.onchange=()=>{st.dept=dp.value;draw()};
 document.querySelectorAll("#period button").forEach(b=>b.onclick=()=>{st.days=+b.dataset.d;draw()})}
function draw(){document.querySelectorAll("#period button").forEach(b=>b.setAttribute("aria-pressed",+b.dataset.d===st.days));
 document.getElementById("sub").textContent=`Data ${D.start} to ${D.end} · made ${D.generated}`;
 document.getElementById("note").textContent=st.dev?"Showing: "+devName(st.dev):"";
 legend("lg1");legend("lg2");drawKpi();drawTime();drawApps();drawHeat();drawDevices();drawSites();drawInsights()}
fillSelects();draw();matchMedia("(prefers-color-scheme: dark)").addEventListener("change",draw);
</script></body></html>"""
