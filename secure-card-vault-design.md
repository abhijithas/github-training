# Secure Offline Credit Card Vault - Android App Design

## Context

Build an Android app for securely storing credit card information locally on-device. All data must be encrypted at rest, the app must work fully offline with zero network access, and authentication must use the device's biometric/PIN mechanisms. This is a personal-use card wallet, not a payment processor.

**Regulatory note**: PCI DSS prohibits storing CVV after payment authorization. Since this is a personal reference vault (not processing transactions), it falls outside PCI DSS scope. However, CVV storage should be optional and clearly explained to the user.

---

## Framework Recommendation: Native Android (Kotlin + Jetpack Compose)

**This is the only viable choice for this threat model.** The reasoning:

| Criterion | Native Kotlin | Flutter | React Native |
|---|---|---|---|
| CryptoObject binding | Direct, first-class | Not supported by `local_auth` (boolean gate only, known vulnerability) | Requires native bridge |
| Keystore/StrongBox | Direct API | Plugin required | Community wrapper |
| Attack surface | Minimal (ART only) | Dart VM + engine | JS runtime + bridge (decompilable via hermes-dec) |
| FLAG_SECURE | First-class | Platform channel | Native module |
| Obfuscation | R8 (deeply integrated) | Limited | Hermes bytecode is reversible |

**The critical differentiator**: Only native Kotlin provides `BiometricPrompt.CryptoObject` binding, where the decryption key is physically locked in the TEE/StrongBox until biometric verification succeeds at the hardware level. Flutter's `local_auth` returns a boolean that can be trivially bypassed with Frida on a rooted device.

---

## Security Architecture

### Encryption: Two-Tier Key Envelope (KEK/DEK)

```
Master Key (KEK)                  -- Android Keystore (TEE/StrongBox)
  |                                  biometric-bound, non-extractable
  | wraps/unwraps
  v
Data Encryption Key (DEK)         -- AES-256, generated via SecureRandom
  |                                  stored encrypted in app-private storage
  | encrypts
  v
Card Data                         -- SQLCipher (page-level) + Tink AEAD (field-level)
```

**Why two tiers?**
- KEK is biometric-bound; every `Cipher.init()` would require a prompt. DEK is unwrapped once per session.
- Key rotation only requires re-wrapping DEK, not re-encrypting the entire database.
- SQLCipher expects a passphrase, not a Keystore handle. DEK bridges that gap.

### Algorithms

| Purpose | Algorithm | Notes |
|---|---|---|
| Database encryption | AES-256-CBC (SQLCipher pages) | Industry standard for SQLite encryption |
| Field-level encryption | AES-256-GCM (via Tink AEAD) | Authenticated encryption for PAN, CVV |
| KEK | AES-256-GCM (Keystore) | Hardware-backed, biometric-bound |
| PIN key derivation | Argon2id (m=64MB, t=3, p=1) | Memory-hard, resists GPU attacks on low-entropy PINs |
| IVs | 96-bit via SecureRandom | Never reused with same key |

### Hardware Security

- Target TEE baseline with opportunistic StrongBox upgrade (runtime detection via `PackageManager.FEATURE_STRONGBOX_KEYSTORE`)
- StrongBox is 35-55x slower for symmetric ops, but KEK only does one wrap/unwrap per session
- Set `setInvalidatedByBiometricEnrollment(true)` -- requires PIN fallback for key recovery after new biometric enrollment

---

## Authentication Flow

### Biometric Path (Primary)
1. Load KEK from Keystore
2. Init `Cipher` for DEK unwrapping (fails until biometric auth)
3. Wrap cipher in `BiometricPrompt.CryptoObject`
4. On `onAuthenticationSucceeded`: use unlocked cipher to decrypt DEK
5. Open database with DEK as SQLCipher passphrase

### PIN Path (Fallback)
1. User enters PIN
2. Derive 256-bit key via Argon2id(PIN, stored salt)
3. Use derived key to AES-256-GCM decrypt the DEK blob
4. Open database with DEK

**Why separate PIN handling (not `DEVICE_CREDENTIAL`)?** The system fallback bypasses `CryptoObject` binding and may accept weak patterns/swipes. Our own Argon2id path provides cryptographically meaningful auth.

### Session Management

| Event | Action |
|---|---|
| App backgrounded > 30s (configurable) | Lock: zero DEK, close DB |
| Screen off (`ACTION_SCREEN_OFF`) | Immediate lock |
| 5 min foreground inactivity | Lock |
| View full PAN or CVV | Re-authenticate even within active session |
| Delete card | Re-authenticate |

---

## Data Storage

### Technology Stack

| Layer | Library |
|---|---|
| ORM | Room 2.7.x |
| DB encryption | sqlcipher-android 4.9.x |
| Field encryption | Tink Android 1.15.x |
| Preferences | DataStore + Tink AEAD (EncryptedSharedPreferences is deprecated) |
| Biometric | androidx.biometric 1.2.x |
| PIN KDF | org.signal:argon2 |

### Schema

```sql
CREATE TABLE cards (
    id              TEXT PRIMARY KEY,    -- UUID
    pan_encrypted   BLOB NOT NULL,       -- Tink AEAD ciphertext
    cvv_encrypted   BLOB,               -- Tink AEAD ciphertext (optional)
    pan_last_four   TEXT NOT NULL,        -- For masked display without decryption
    cardholder_name TEXT NOT NULL,
    card_nickname   TEXT,
    expiry_month    INTEGER NOT NULL,
    expiry_year     INTEGER NOT NULL,
    card_network    TEXT,                -- Visa/MC/Amex (derived from BIN at entry)
    card_color      TEXT DEFAULT '#1E88E5',
    card_icon       TEXT DEFAULT 'default',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    encryption_key_version INTEGER NOT NULL DEFAULT 1
);
```

**Double encryption rationale**: SQLCipher encrypts the DB file at the page level. Tink AEAD additionally encrypts PAN/CVV fields individually. If SQLCipher is compromised or the passphrase leaks via memory dump, the most sensitive fields remain independently encrypted.

---

## Data Leakage Prevention

1. **Screenshots/screen recording**: `FLAG_SECURE` on every Activity
2. **App switcher**: Blank preview (automatic with FLAG_SECURE)
3. **Network**: No `INTERNET` permission in manifest + `tools:node="remove"` to block library merges
4. **Backups**: `allowBackup=false` + `dataExtractionRules` excluding everything
5. **Clipboard**: `EXTRA_IS_SENSITIVE` flag + 30s auto-clear
6. **Accessibility services**: `accessibilityDataSensitive=true` (API 34+) on card data views
7. **Keyboard logging**: Custom in-app numeric keypad for card number entry (bypasses third-party IMEs)
8. **Memory**: Use `ByteArray` (not `String`) for sensitive data; zero after use via `fill(0)`
9. **Obfuscation**: R8 with aggressive minification for release builds

---

## UX Security Design

- **Card list**: Show only `**** **** **** 4242` using stored `pan_last_four`
- **Reveal full number/CVV**: Requires fresh biometric/PIN auth, auto-hides after 30s countdown
- **Onboarding** (3 screens):
  1. "Your cards never leave this device" - no cloud, no sync, no backup
  2. "Protected by hardware encryption" - explain TEE/StrongBox
  3. "Set up your unlock" - biometric enrollment + mandatory PIN backup
- **Data loss warning**: Clearly state that forgotten PIN = unrecoverable data (by design)

---

## Additional Security

- **Root/tamper detection**: Check `Build.TAGS`, `su` binary, Magisk presence, APK signature verification (raise-the-bar, not foolproof)
- **Auto-lock timeout**: User-configurable (immediate / 15s / 30s / 1m / 5m)
- **Failed PIN attempts**: Escalating lockout (30s -> 1m -> 5m -> 15m) with optional data wipe after N attempts
- **Key rotation**: KEK rotation = re-wrap DEK with new key; DEK rotation = SQLCipher `PRAGMA rekey` + re-encrypt Tink fields
- **Biometric invalidation**: Catch `KeyPermanentlyInvalidatedException`, fall back to PIN path, generate new KEK

---

## Project Structure

```
app/src/main/
  AndroidManifest.xml
  java/com/example/cardvault/
    crypto/
      KeyManager.kt              -- Keystore KEK, DEK wrap/unwrap, StrongBox detection
      TinkManager.kt             -- Field-level AEAD for PAN/CVV
      Argon2KeyDeriver.kt        -- PIN -> derived key
      SecureByteArray.kt         -- Zeroing wrapper
    auth/
      BiometricAuthManager.kt    -- BiometricPrompt + CryptoObject
      PinAuthManager.kt          -- PIN validation, attempt tracking, lockout
      SessionManager.kt          -- Session state, timeout, re-auth triggers
    data/
      db/
        AppDatabase.kt           -- Room + SQLCipher SupportFactory
        CardDao.kt
        CardEntity.kt
      repository/
        CardRepository.kt        -- Encrypt/decrypt fields via TinkManager
      datastore/
        SecurePreferences.kt     -- DataStore + Tink for settings
    security/
      IntegrityChecker.kt        -- Root detection, APK signature verification
      ClipboardManager.kt        -- Sensitive copy + auto-clear
      ScreenSecurityManager.kt   -- FLAG_SECURE, accessibility flags
    ui/
      SecureActivity.kt          -- Base Activity with FLAG_SECURE
      onboarding/
      cardlist/
      carddetail/                -- Reveal-on-demand with re-auth
      cardinput/                 -- Custom numeric keypad
      settings/
      pin/
  res/xml/
    data_extraction_rules.xml
```

---

## Dependencies

```kotlin
dependencies {
    // Room + SQLCipher
    implementation("androidx.room:room-runtime:2.7.0")
    implementation("androidx.room:room-ktx:2.7.0")
    ksp("androidx.room:room-compiler:2.7.0")
    implementation("net.zetetic:sqlcipher-android:4.9.0")

    // Tink (field-level AEAD)
    implementation("com.google.crypto.tink:tink-android:1.15.0")

    // Biometric
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    // DataStore
    implementation("androidx.datastore:datastore-preferences:1.1.2")

    // Argon2 (Signal's JNI binding)
    implementation("org.signal:argon2:13.8.4")

    // Compose
    implementation(platform("androidx.compose:compose-bom:2025.03.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")

    // Lifecycle (session management)
    implementation("androidx.lifecycle:lifecycle-process:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
}
```

---

## Verification Plan

1. **Encryption**: Extract `vault.db` via ADB from a debug build, attempt to open with DB Browser for SQLite -- should fail (encrypted)
2. **Biometric binding**: Set breakpoint after `BiometricPrompt.authenticate()`, verify cipher is unusable without successful auth callback
3. **No network**: Run `adb shell dumpsys package <pkg> | grep permission` -- verify no INTERNET permission in merged manifest
4. **FLAG_SECURE**: Attempt screenshot while app is open -- should be blocked
5. **Clipboard**: Copy a card number, wait 30s, paste -- should be empty
6. **Backup**: Run `adb backup` -- should produce empty/denied result
7. **Session lock**: Background app for >30s, return -- should require re-auth
8. **PIN lockout**: Enter wrong PIN 3+ times -- verify escalating delays
9. **Memory**: Use Android Studio Memory Profiler, search heap for card numbers after session lock -- should not be found
10. **Root detection**: Test on rooted emulator -- should display warning
