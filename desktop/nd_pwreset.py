# -*- coding: utf-8 -*-
"""Regain access to YOUR OWN device when you forgot its password - the official, manufacturer-supported way.

This is NOT a password cracker and does not attempt any passwords. Cracking a password works the same on a
device that isn't yours, so it is not something this app will ever do. Instead, every camera / NVR / DVR / router
brand has an OFFICIAL reset the owner can use (a physical reset button, a vendor tool, or a date-based code the
manufacturer issues from the device serial). That is faster and more reliable than any attack, and it only works
for someone with physical/owner access to the device - which is the point. This module maps the brand Network
Doctor already detected to the right official steps, so the owner is pointed at the real fix."""

# brand key -> (title, ordered steps). Keys are matched case-insensitively against vendor/name/web text.
_RESET = {
    "hikvision": ("Hikvision camera / NVR - official password reset", [
        "Install Hikvision's free 'SADP' tool on a PC on the same network (hikvision.com > Support > Tools).",
        "Open SADP - it lists your device with its serial number and 'start time'.",
        "Select the device, click 'Forgot Password'. Choose the reset mode it offers (export file, or security code).",
        "For the export-file mode: SADP saves an XML; send it to Hikvision support (or your dealer) who returns a "
        "code file, which you load back in SADP to set a new password.",
        "Newer firmware: answer the security questions you set, or use the linked Hik-Connect account to reset.",
        "No tools: hold the device's physical RESET button ~10-20 s while powered on to return it to factory "
        "(this wipes its settings, then you set a new password on first login)."]),
    "dahua": ("Dahua camera / NVR - official password reset", [
        "On the NVR/camera login screen, click 'Forgot password' - it shows a QR code.",
        "Scan the QR with the Dahua 'DMSS' app (or email the QR to support@dahuatech.com) to get a reset code.",
        "Enter the code on the device within its time window to set a new password.",
        "If you set security questions at setup, answer them instead.",
        "Last resort: the physical RESET button held ~5 s on a powered device factory-resets it."]),
    "xmeye": ("XMeye / generic (Sofia) NVR - official password reset", [
        "On the device login, note the DATE shown and the device's serial / 'ID'.",
        "Use the maker's 'super password' / date-code flow: the XMeye app > Forgot password, or ask your dealer "
        "for the day's reset code generated from the serial + today's date.",
        "Enter the code to set a new password (the code is only valid for that date).",
        "Physical RESET: many of these have a reset point on the board / a button - hold while powered to factory "
        "reset (wipes config), then set a new password."]),
    "cp plus": ("CP Plus NVR - official password reset", [
        "On the login screen tap 'Forgot Password' for the QR code.",
        "Scan it in the CP Plus 'gCMOB'/'iCMOB' app, or email it to CP Plus support, to get the day's reset code.",
        "Enter the code on the device to set a new password."]),
    "router": ("MikroTik router - you already have access", [
        "You are logged in to this router from Network Doctor, so you don't need to crack anything.",
        "Your Wi-Fi password is readable here: it's shown under the router's wireless config (Show Wi-Fi password).",
        "To change the router's own login, update the user in the router's own Users settings - don't "
        "factory-reset unless you must."]),
}

_GENERIC = ("Camera / NVR - regain access the official way", [
    "Find the brand (Network Doctor shows the vendor on the device row) and open that maker's app or support site.",
    "Every brand has a 'Forgot password' flow: a QR code scanned in the maker's phone app, security questions you "
    "set, or a date-based reset code the maker issues from the device serial.",
    "A physical RESET button (held while powered) factory-resets any of them - this wipes the device's settings, "
    "after which you set a brand-new password on first login.",
    "If it's on a dealer's AMC, the dealer can reset it for you - that's the fastest route."])


def reset_guide(brand_or_text):
    """Return (title, [steps]) for the best-matching brand, or a generic owner-reset guide. Input is any text
    about the device (vendor, name, web banner). Never attempts a password - this is guidance only."""
    t = (brand_or_text or "").lower()
    for key, guide in _RESET.items():
        if key in t:
            return guide
    # common sub-brands that use the same flow
    if any(w in t for w in ("sofia", "netsurveillance", "general", "xiongmai")):
        return _RESET["xmeye"]
    if any(w in t for w in ("mikrotik", "routeros")):
        return _RESET["router"]
    return _GENERIC


def guide_text(brand_or_text):
    title, steps = reset_guide(brand_or_text)
    return title + "\n\n" + "\n".join("%d. %s" % (i + 1, s) for i, s in enumerate(steps)) + \
        "\n\nNote: this is the official owner reset. Network Doctor does not crack passwords - a cracker would " \
        "work on devices that aren't yours, so it is never built in. These steps need owner/physical access, " \
        "which is the safe, legitimate way back into your own device."
