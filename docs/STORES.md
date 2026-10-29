# Publishing Network Doctor in the app stores

**Already done, with no store needed:**
- Windows and Mac downloads that update themselves from GitHub.
- An Android test APK.

Store publishing needs a developer account for each store. Only you can register these, because they need your identity or company documents and payment. Once each account exists, the remaining work is mostly automatic.

| Store | Account | Cost | Status |
|---|---|---|---|
| Google Play (Android) | Google Play Console | One-time registration fee (US $25) | App and automatic build ready; waiting for the account |
| Microsoft Store (Windows) | Microsoft Partner Center | Free for individuals and companies | Waiting for the account; then an MSIX build is added |
| Mac | Apple Developer Program | US $99 per year | Download works now; the account only removes the "unidentified developer" warning |

---

## 1. Google Play (Android)

### Choose the account type

| | Organization account (FanAir India Pvt. Ltd.) | Personal account |
|---|---|---|
| Needs | A **D-U-N-S number** for the company (free from Dun & Bradstreet, takes a few days to a few weeks), and the company website, email and phone verified | Your ID verification |
| Before going public | Nothing extra | A **closed test with at least 12 testers for 14 days in a row** (Google rule for new personal accounts) |
| Shown as developer | FanAir India Pvt. Ltd. | Your name |

**Recommended:** an organization account, unless you can't get the D-U-N-S number soon.

### Steps

1. Sign up at <https://play.google.com/console/signup>, pay the one-time fee and finish identity verification.
2. **Tell Claude the account is ready.** Claude will then:
   - create the **upload key** (the file that proves updates come from you);
   - give you 4 secret values. You paste them into GitHub yourself: repository → **Settings → Secrets and variables → Actions → New repository secret**. The names are:
     - `ANDROID_KEYSTORE_BASE64`
     - `ANDROID_KEYSTORE_PASSWORD`
     - `ANDROID_KEY_ALIAS`
     - `ANDROID_KEY_PASSWORD`
   - From then on, every build also produces `NetworkDoctor-Android.aab`, the file Google Play needs.
   - Claude will also prepare the store listing: short and full description, a 512×512 icon, a 1024×500 feature graphic and phone screenshots.
3. In Play Console, choose **Create app**: name *Network Doctor*, type **App**, **Free**.
4. Fill in **App content**:
   - **Privacy policy URL:** `https://github.com/yadavrkpacheriya/network-doctor/blob/main/PRIVACY.md`
   - **Data safety:** no data collected, no data shared.
   - **Ads:** no ads.
   - **Target audience:** 18+. It is a tool for network administrators.
   - **Content rating:** answer the questionnaire. It is a utility with no user content.
5. Go to **Testing → Internal testing → Create release**, upload the `.aab` from the GitHub Actions run, add yourself as a tester and install it from Play.
6. When happy, promote it:
   - personal account: closed testing for 14 days with 12 testers, then **Production**;
   - organization account: straight to **Production**.

**Package name:** the app's ID on Google Play is `com.pacheriya.networkdoctor` (chosen 29 Oct 2026). It can never change after the first upload to Play.

**Updates:** raise `version:` in `mobile/pubspec.yaml`. GitHub then builds a new signed `.aab`, which you upload in Play Console. Uploading can be automated later with a Google Play service account.

---

## 2. Microsoft Store (Windows)

1. Register at <https://storedeveloper.microsoft.com> (Partner Center). It is free as an individual or as FanAir India Pvt. Ltd.
2. Choose **Create a new app → MSIX or PWA app** and reserve the name **Network Doctor**.
3. Open **Product management → Product identity** and send Claude these three values:
   - `Package/Identity/Name`
   - `Package/Identity/Publisher`
   - `Package/Properties/PublisherDisplayName`
4. Claude adds an **MSIX** build to the GitHub workflow.

**Why MSIX:**
- Microsoft signs the package itself, so Store users never see *"Windows protected your PC"*.
- You don't need to buy a code-signing certificate.
- The Store installs updates automatically.

**What changes in the Store version:**
- The app starts normally, without asking for administrator rights.
- For the full IP-conflict and duplicate-reply tests, it uses its **Restart as Administrator** button. This needs a capability Microsoft reviews during certification, so they may ask why. The answer: *network diagnostics: IP-conflict and loop tests need raw network access*.

The alternative route is to submit the existing `.exe` as an installer. Microsoft then requires it to be signed with a paid code-signing certificate, about US $150–300 per year.

The GitHub download of `NetworkDoctor.exe` stays available alongside the Store version and keeps updating itself.

---

## 3. Mac

- **Now, without an Apple account:** download `NetworkDoctor-macOS.zip` from the latest release. The first time, **right-click → Open**, or **System Settings → Privacy & Security → Open Anyway**.
- **With the Apple Developer Program (US $99/year):** Claude adds signing and Apple notarization to the GitHub build, so the app opens with no warnings. This needs the account's *Developer ID Application* certificate and an app-specific password. You add those as GitHub secrets yourself.
- **Mac App Store: not recommended.** Apple requires App Store apps to run in a "sandbox". The sandbox blocks running ping, reading the ARP table and receiving the router log, which would remove most of what Network Doctor does. The signed and notarized download above gives the same trust with all features.

---

## 4. Optional: remove the Windows warning for the GitHub download too

The *"Windows protected your PC"* warning on the GitHub download goes away only with a code-signing certificate. There are two options:

- **A paid OV certificate:** about US $150–300 per year, available in India.
- **[SignPath Foundation](https://signpath.org):** free signing for open-source projects. It requires adding an open-source licence (for example MIT) to the repository, which lets anyone reuse the code. This is your business decision.
