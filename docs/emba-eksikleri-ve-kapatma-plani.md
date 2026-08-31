# EMBA'nın Credential Taramasındaki Eksikler ve LAVA'nın Kapatma Planı

> Çalışma notu — `custom_scan.py` + profil sistemi tasarımı için temel.
> Kaynak: EMBA modül kaynak kodları (`emba/modules/S45,S99,S106,S107,S108`),
> `emba/config/*.cfg`, ve LAVA'nın `EMBA - Scan Profile/lava.00-quick-scan.emba`
> blacklist'i. İncelenen tarih: 2026-08-30.

---

## 0. Bir cümlede

EMBA'nın LAVA'da aktif olan credential modülleri ya **çok dar** (S107 = sadece 7
crypt-hash regex'i, cleartext yok), ya **dosya-adına bağlı** (S45), ya da
**kaynak-kod denetimi için tasarlanmış, gürültülü** (S99 = crass). Ayrıca LAVA
kendi hız profilinde EMBA'nın credential'a yakın **8+ modülünü kapatmış**.
Eksiği `custom_scan.py` adında, kullanıcı-düzenlenebilir kural profilleriyle
çalışan bir ara katmanla kapatacağız; bu katman extract edilmiş dosya sistemini
kendi kalıplarımızla tarayıp bulgularını EMBA bulgularıyla **aynı şemada**
pipeline'a verecek.

---

## 1. EMBA credential modülleri — gerçekte ne yapıyorlar

LAVA'nın `parser.py`'sinin okuduğu 5 modül:

| Modül | Kapsam (tam) | EMBA kaynağı |
|---|---|---|
| **S45** `pass_file_check` | `config/pass_files.cfg` glob'una uyan dosyaları bulur: `*/*passw*`, `*/*shadow*`, `*/master.passwd`, `*/.git-credentials`. Bu dosyalar içinde `/etc/passwd` ve `/etc/shadow` **formatındaki satırları** parse eder (`:x:` `:*:` `:!:` hariç), uid=0 hesaplarını ve `sudoers`'ı çıkarır. → Dosya **adı** eşleşmezse hiç bakmaz. | `modules/S45_pass_file_check.sh`, `config/pass_files.cfg` |
| **S106** `deep_key_search` | Tüm `firmware/` ağacında `grep -r` — **sadece 2 regex**: `-----BEGIN .*PRIVATE KEY-----`, `-----BEGIN .*AES KEY-----`. Eşleşen dosya + ±2 satır. | `modules/S106_deep_key_search.sh`, `config/deep_key_search.cfg` |
| **S107** `deep_password_search` | Tüm dosyalarda `grep -f config/password_regex.cfg` + eşleşen dosyada `strings`. Config = **sadece 7 crypt() hash formatı**: `$1$` `$5$` `$6$(8/12/16)` `$2[abxy]$` `$y$`. **Cleartext parola sıfır.** | `modules/S107_deep_password_search.sh`, `config/password_regex.cfg` |
| **S108** `stacs_password_search` | Harici **STACS** motoru + community `credential.json` ruleset. Entropi + regex; PEM/PKCS8/PuTTY key, AWS/GCP anahtarı, yüksek-entropili string'ler. Git-repo / CI artefaktı için tuned; gömülü-Linux config deyimlerini bilmez, binary'de gürültülü (`--skip-unprocessable`). | `modules/S108_stacs_password_search.sh` (stacs kurulu değilse atlanır) |
| **S99** `grepit` | `floyd-fuh/crass` **kaynak-kod audit** kalıp kütüphanesi (`grepit_module_*` fonksiyonları script içinde gömülü). Cred ilgili: `password:` `password=` `pass.?wo?r?d` `se?cre?t.{0,N}=["'\d]` `pass.?phrase.{0,N}=` `PW.?=` `credentials` `default.?password` vb. | `modules/S99_grepit.sh` (~5000 satır) |

**S99'un yapısal sınırları** (LAVA `parser.py`'de de görülüyor):
- Modülleri dile göre (`java/php/python/js/...`) — firmware rootfs deyimleri (UCI,
  nvram, init.d) onun dünyasında yok.
- **Grep-context bloğu başına sadece İLK eşleşme** kaydedilir → 5 secret satırlı
  config = 1 bulgu.
- **Değeri çıkarmaz**; "gerçek değer mi, değişken adı/placeholder mı" kararı
  tamamen LLM'e bırakılır.
- Devasa binary gürültü → LAVA `content_is_mostly_printable` +
  `S99_CATEGORY_WHITELIST` (~30 kategori) ile eler, gerisini atar.

---

## 2. EMBA nelere BAKMIYOR

Üç ayrı katman var. Karıştırmamak önemli.

### 2.1 Hiç bakmıyor — modül de kalıp da yok

**A. Cleartext key=value, "password" olmayan anahtar isimleriyle**
Gömülü cihaz config deyimlerinde secret taşıyan ama S99'un `pass/secret/passphrase`
listesine düşmeyen anahtarlar:
```
psk, wpa_psk, wl_wpa_psk, wl_wpa_psk_1..N, wpa_passphrase   (Wi-Fi)
auth_pass, http_passwd, login_pass, admin_pwd, sys_pass, user_pass
PPP_PASSWORD, pppoe_passwd, chap_password, chap-secret
mqtt_password, rtsp_password, onvif_password, rtsp_key       (kamera)
db_pass, mysql_pwd, pg_password, requirepass                 (Redis)
snmp community, rocommunity, rwcommunity, community private  (SNMP r/w string
                                                             = credential)
nvram_default ...pass, nvram set <x>passwd ...
```

**B. Format / encoding katmanı**
- `Authorization: Basic <base64>` → decode → `user:pass`  (EMBA hiç decode etmiyor)
- Genelleştirilmiş connection string: `(?i)[a-z][a-z0-9+.-]*://[^/:\s]+:(?P<pw>[^@\s]+)@`
  — S99'da sadece **literal örnekler** var (`http://username:password@example.com`),
  gerçek regex değil.
- OpenSSH **public/authorized** key formatı: `ssh-(rsa|ed25519|dss) AAAA...`,
  `ecdsa-sha2-...` — S106 sadece PEM `-----BEGIN-----` bloğunu görüyor, bunu değil.
- Bilinen API-key prefix'leri geniş kapsamda: `AKIA…` (AWS), `AIza…` (Google),
  `ghp_/gho_/ghs_`, `xox[baprs]-` (Slack), `sk_live_` (Stripe), `SG.` (SendGrid),
  `eyJ…` (JWT). S99'un `api_keys` modülünde birkaç vendor var ama audit listesi,
  kapsamlı değil.

**C. Dosya-formatı-farkında parsing** (regex değil, mini-parser)
- `.htpasswd`, `chap-secrets`, `ppp/*-secrets` → alan bazlı
- `wpa_supplicant.conf` / `hostapd.conf` → `psk=`, `wpa_passphrase`
- `smb.conf`, `vsftpd.conf`, `proftpd`, `dropbear_*`, `sshd_config`
- **`/etc/passwd` × `/etc/shadow` korelasyonu**: S45 sadece adı `*shadow*` olan
  dosyaya bakıyor; adı farklıysa (ör. `defcfg`, `board.json`, `.htpasswd`)
  hangi kullanıcının gerçek hash'i olduğunu kimse eşleştirmiyor.

**D. Binary içindeki gömülü credential + bağlam**
S107 sadece `strings | grep <hash-regex>` yapıyor (yalnız hash). Auth daemon'ın
(`.so`, cgi binary) içine gömülü cleartext admin parolası + çağrıldığı fonksiyon
bağlamı → kimse bakmıyor.

### 2.2 EMBA'da modül VAR ama LAVA scan-profile'ında KAPALI

`EMBA - Scan Profile/lava.00-quick-scan.emba` → `MODULE_BLACKLIST` içinde
(hız için kapatılmış), credential'a yakın olanlar:

| Modül | Ne yapardı |
|---|---|
| `S85_ssh_check` | SSH host key'leri, `authorized_keys`, zayıf `sshd_config`, dropbear |
| `S60_cert_file_check` | Sertifikalar + eşleşen private key'ler, paylaşımlı/zayıf anahtar |
| `S65_config_file_check` | `network_conf_files.cfg` listesindeki config'lerin taranması |
| `S50_authentication_check` | PAM dosyaları, `/etc/passwd` analizi, auth zayıflıkları |
| `S55_history_file_check` | `.bash_history` vb. içindeki parolalar |
| `S40_weak_perm_check` | Dünyaya-yazılır/ okunur hassas dosyalar (shadow 0644 gibi) |
| `S80_cronjob_check` | Cron scriptlerinde gömülü credential |
| `S95_interesting_files_check` | `linux_common_files.txt` — ilginç dosyalar |
| `S90_mail_check` | Mail config'lerinde SMTP credential |
| `S36_lighttpd` / `S35_http_file_check` | Web sunucu config'lerinde `.htpasswd`, auth |

Bunlar "EMBA bakmıyor" değil — **biz baktırmıyoruz**. Karar: bir kısmını
profilde geri açmak vs. işe yarar kısmını `custom_scan`'de replikle (bkz. §3.5).

### 2.3 Bakıyor ama zayıf / gürültülü

- **S99**: whole-line dump, blok başına ilk eşleşme, değer çıkarmıyor, kaynak-kod
  odaklı. Aynı config'teki 2. secret satırını kaçırır.
- **S45**: içerik parse'ı iyi ama sadece adı glob'a uyan dosyada. `board.json`
  içindeki `"root_password_hash": "$6$..."` → S45 görmez (S107 görür ama sadece
  hash formatındaysa).
- **S108**: STACS repo/CI için tuned; `option key 'xxx'` (UCI) gibi deyimleri
  bilmez; stacs kurulu değilse **komple atlanır** (sessizce).
- **S106**: 2 pattern. `-----BEGIN OPENSSH PRIVATE KEY-----` yakalar ama
  `PuTTY-User-Key-File`, `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----` (RFC4716),
  inline base64 blob'ları kaçırabilir (regex `.*PRIVATE KEY` bazılarını tutar,
  bazılarını tutmaz — test lazım).

---

## 3. Biz eksikleri nasıl kapatacağız

### 3.1 `custom_scan.py` — kendi grep/strings katmanı

`parser.py`'ye **paralel** yeni modül. `[1]` (parse) ile `[1c]` (merge) arasına girer.

```
python3 src/core/custom_scan.py --log-dir <LOG> --profile <P> --out custom_findings.json
```

Yaptığı iş:
1. Extraction root'u bul (ortak `fw_paths.py` — `enricher.find_extraction_roots`
   mantığı buraya taşınır).
2. Profili yükle (`extends` çöz → birleşik kural seti).
3. `include/exclude` glob + `max_file_size` + binary atlama (NUL byte) ile dosyaları gez.
   **Hız:** kural union'ını tek pattern dosyasına yazıp `rg --json` çağır
   (ripgrep 14.x sistemde kurulu). Saf Python fallback opsiyonel.
4. Her eşleşmede:
   - `value_group`'u çıkar → `reject_values` (placeholder/label filtresi),
     `content_is_mostly_printable`, token kuralları için Shannon entropisi eşiği.
   - `strings_rules` açıksa binary'de `strings` çıktısında ara (varsayılan KAPALI).
5. `new_finding("CUSTOM:<rule_id>", normalize_path(path), matched_line,
   {"profile":P, "rule":id, "line_no":N, "value":v})` — **parser.py ile birebir
   aynı `new_finding`** + **her zaman `line_no`** (enricher exact context için).
6. Cap: rule başına ≤ N, toplam ≤ M, `(file_path, line_no, rule_id)` dedup.
7. `custom_findings.json` — `parser.py --out` ile aynı şekil (finding listesi).

### 3.2 Kural / profil şeması

`config/scan_profiles/*.yaml` (shipped) + `config/scan_profiles/local/*.yaml`
(`.gitignore` — kullanıcı). Format YAML (okunaklı; `pyyaml` bağımlılığı — MVP'de
JSON de olur).

```yaml
name: generic
extends: null
include_paths: ["etc/**", "**/*.conf", "**/*.cfg", "**/*.ini", "**/*.sh", "www/**",
                "**/*.json", "**/*.xml", "usr/lib/**/*.lua"]
exclude_paths: ["**/*.so*", "**/*.ko", "usr/share/locale/**", "**/*.min.js"]
max_file_size_kb: 512
text_files_only: true

rules:
  - id: cleartext_password_assign
    pattern: '(?i)\b(pass(word)?|passwd|pwd|psk|auth[_-]?pass)\b\s*[:=]\s*["'']?(?P<value>[^\s"'';#]{3,80})'
    value_group: value
    reject_values: ['x', '\*+', '(?i)password|changeme|admin|<.*>|\$\{.*\}|%s|none|null|123456|0000']
  - id: private_key_inline
    pattern: '-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'
    multiline: true
  - id: ssh_pubkey_authorized
    pattern: '(?P<value>(ssh-(rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9-]+) AAAA[0-9A-Za-z+/]{40,})'
    value_group: value
  - id: basic_auth_header
    pattern: '(?i)authorization:\s*basic\s+(?P<value>[A-Za-z0-9+/]{12,}={0,2})'
    value_group: value
    decode: base64            # custom_scan value'yu decode edip user:pass olarak da not eder
  - id: conn_string_cred
    pattern: '(?i)[a-z][a-z0-9+.\-]*://[^/:\s]+:(?P<value>[^@\s/]{3,})@'
    value_group: value
  - id: api_token_prefix
    pattern: '(?P<value>AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{36})'
    value_group: value
  - id: snmp_community
    pattern: '(?i)\b(ro|rw)?community\b\s+(?P<value>[^\s#"'']{2,})'
    value_group: value
    reject_values: ['public', 'private']        # not: public/private default → ayrı, düşük confidence

strings_rules:
  enabled: false
  min_len: 6
  patterns:
    - '(?i)admin:[^:\s]{4,}'

# --- cihaz profili için ek alanlar (generic'te boş) ---
match: {}
ai: {}
```

Cihaz profili örneği (`router-openwrt.yaml`):
```yaml
name: router-openwrt
extends: generic
match:
  any_path_exists: ["sbin/uci", "etc/config/system", "etc/openwrt_release"]
  banner_regex: ["OpenWrt", "LEDE"]
  package_manager: "opkg"
rules:
  - id: uci_secret_option
    pattern: "option (password|key|psk|auth_secret) '(?P<value>[^']{3,})'"
    value_group: value
  - id: nvram_default_cred
    pattern: '(?i)(http_passwd|admin_pass|PSK|wl_wpa_psk[0-9_]*)\s*=\s*(?P<value>\S{3,})'
    value_group: value
ai:
  device_class: "SOHO router running OpenWrt/LEDE"
  extra_rules: |
    - etc/config/* içinde `option password/key/psk` gerçek değerle → TP; boş '' → FP.
    - Wi-Fi PSK default görünse bile TP (cihazdan çıkarılabilir credential).
  few_shot_add:
    - {file_path: "etc/config/wireless", matched_content: "option key 'admin1234'",
       verdict: TP, reasoning: "Cleartext WPA PSK in UCI config."}
```

### 3.3 Pipeline'a bağlama

`run_lava.sh` (local / gemini dalı):
```
[1]  parser.py                         → findings.json
[1b] custom_scan.py --profile $P       → custom_findings.json
[1c] parser.py --extra-findings custom_findings.json   (all_findings'e katıp
     merge_and_corroborate'i TEK noktada çalıştır)      → merged_findings.json
[2]  enricher.py                       → enriched_findings.json
[3]  classifier.py --profile $P
[4]  html_report.py
```

**Merge sorunu (kritik):** `merge_and_corroborate` anahtarı
`(file_path, matched_content)` **birebir string**. Custom kural S99 satırını
yakalarsa `matched_content` aynı → merge olur, `corroboration_count++`. Ama S107
sadece **hash string'ini** saklıyor (satırı değil) → custom kural aynı satırı
yakalasa bile `matched_content` farklı → merge OLMAZ.
→ **Çözüm:** `merge_and_corroborate`'e ikincil bir anahtar ekle:
`(file_path, line_no)` eşleşenler de aynı gruba girsin (line_no varsa).

MCP dalı: parser/enricher atlandığı için `custom_scan.py` yine koşsun,
`lava_mcp_server.build_registry` `custom_findings.json`'ı da yüklesin.

`classifier.py`:
- `SYSTEM_PROMPT_TEMPLATE`'e `{device_context}` + `{profile_extra_rules}` slotu.
- `build_system_prompt(few_shot, profile=None)` — profil `ai:` bloğunu enjekte eder.
- `_build_agent_prompt` zaten `build_system_prompt` çağırıyor → otomatik alır.
- Prompt'a kısa not: "bazı bulgular EMBA'dan değil, LAVA'nın kendi cleartext
  kalıplarından; `extra.value` aday secret'tır; `CUSTOM:` içeren
  `found_by_modules` bir corroboration sinyalidir."

### 3.4 Cihaz profilleri + AI profilleme

**Seçim (3 mod):**
1. Manuel — `config/ai_config.env` → `SCAN_PROFILE="router-openwrt"` (GUI dropdown).
2. Otomatik — `src/core/profile_detect.py`: her profilin `match:` bloğunu
   extraction root'a karşı puanlar (`any_path_exists`, `banner_regex` →
   `etc/banner`/`etc/issue`/`etc/os-release`, `package_manager` → `opkg`/`ipkg`/`dpkg`
   ikilisi, `www_fingerprint`). En yüksek puan; eşleşme yoksa `generic`.
   (İstersen EMBA `S06_distribution_identification`'ı profilde geri açıp çıktısını
   sinyal olarak kullan.)
3. `extends` — cihaz profili `generic`'in üstüne sadece EKLER.

**AI profilleme** = profil `ai:` bloğu → prompt:
- `ai.device_class` → sistem prompt'una ("You are analyzing a **SOHO router
  (OpenWrt)** …")
- `ai.extra_rules` → `CRITICAL RULES`'a ek satırlar
- `ai.few_shot_add` → `ground_truth.json` `few_shot` ile birleştirilir
- Aynısı MCP `_build_agent_prompt` için (tek kaynak).

### 3.5 EMBA modüllerini seçici geri açma (§2.2 için — tamamlayıcı)

`custom_scan`'de her şeyi yeniden yazmak yerine, ucuz ve yüksek-değerli
EMBA modüllerini LAVA scan-profile'ında geri açmak daha az iş olabilir:
- **`S85_ssh_check`** — SSH key'leri, authorized_keys (yeniden yazmak zahmetli)
- **`S60_cert_file_check`** — cert + key eşleştirme

`parser.py`'ye bu modüllerin çıktısı için `parse_s85`, `parse_s60` eklenir.
Trade-off: EMBA tarama süresi artar (bu modüller görece hızlı) vs. çıktı
şeması üzerinde tam kontrol.
**Öneri:** cleartext `key=value` boşluğu (§2.1-A/B/C) → `custom_scan`;
ssh/cert (§2.2) → EMBA modülünü geri aç.

---

## 4. Fazlar

| Faz | İçerik | Çıktı / amaç |
|---|---|---|
| **1** | `fw_paths.py` (ortak) + `custom_scan.py` + `generic.yaml` (~8 kural) + `parser.py --extra-findings` + `merge_and_corroborate` line_no anahtarı + prompt notu. GUI yok, auto-detect yok. `SCAN_PROFILE` env. | Ground truth'ta EMBA-only vs with-custom fark ölçülür |
| **2** | MCP entegrasyonu (`build_registry` + custom); GUI "Scan Profile" dropdown + "Edit rules"; `config/scan_profiles/local/`; `strings_rules` (opt-in) | Kullanılabilirlik |
| **3** | `profile_detect.py` + `router-openwrt.yaml` / `ipcam-generic.yaml` (`extends` + `ai:`); `classifier` profil-aware prompt; S85/S60 geri açma | Cihaz derinliği |

---

## 5. Değerlendirme (ground truth)

- `ground_truth.json` `test_set` şu an tamamen EMBA-türevi (19 öğe). Custom
  findings eklenince `--mode test` sayıları kayar ve **eski sayılarla
  kıyaslanamaz**.
- Yapılacak: profil başına ~10-15 yeni etiketli örnek (TP + FP), ayrı bir
  `test_set_custom` veya `ground_truth` versiyonlama.
- İzlenecek metrik: "custom scan'in eklediği bulgu sayısı" + "bunların classifier
  TP oranı" → `reject_values` / entropi eşiği / cap ayarını **kanıtla** yap.
- Kırmızı çizgi: custom katman genel precision'ı düşürüyorsa (LLM'e çöp bulgu
  akıtıyorsa) → kural gevşek, sık.

---

## 6. Riskler / açık kararlar

1. **Motor:** kendi mini-engine (0 bağımlılık, tam kontrol) vs. `rg` sarmalama
   vs. trufflehog/semgrep köprüsü. → `key=value` cleartext için kendi engine +
   `rg` hızlandırma öneriliyor.
2. **Kural formatı:** YAML (`pyyaml` bağımlılığı) vs. JSON (0 bağımlılık, çirkin
   regex escape). Kullanıcı düzenleyecek → YAML dostça. MVP JSON olabilir.
3. **Tarama hedefi:** sadece extract FS (öneri) vs. + binary `strings` (opt-in,
   gürültülü) vs. + EMBA logları.
4. **Kullanıcı profilleri nerede:** repo `config/scan_profiles/local/`
   (`.gitignore`) vs. `~/.config/lava/`.
5. **Merge:** `matched_content` normalize mi, `(file_path,line_no)` ikincil
   anahtar mı. → ikincil anahtar daha güvenli.
6. **Lisans:** S99/crass kalıpları GPL — kopyalama, kendi kalıbını yaz.
7. **Auto-detect** şimdi mi (Faz 1) sonra mı (Faz 3). → sonra.

---

## 7. `generic.yaml` — ilk somut kural seti (öncelik sırası)

| # | id | Ne yakalar | Kaynak eksik (§) |
|---|---|---|---|
| 1 | `cleartext_password_assign` | `pass/pwd/passwd/psk/auth_pass = değer` | 2.1-A, 2.3 |
| 2 | `private_key_inline` | tüm PEM `BEGIN … PRIVATE KEY` (rootfs geneli) | 2.1 (S106 dar) |
| 3 | `ssh_pubkey_authorized` | `ssh-rsa/ed25519 AAAA…` (authorized_keys) | 2.1-B |
| 4 | `basic_auth_header` | `Authorization: Basic <b64>` + decode | 2.1-B |
| 5 | `conn_string_cred` | `scheme://user:pass@host` (genel regex) | 2.1-B |
| 6 | `api_token_prefix` | AWS/GCP/Slack/Stripe/GitHub anahtar prefix'leri | 2.1-B |
| 7 | `snmp_community` | `ro/rw community <string>` | 2.1-A |
| 8 | `htpasswd_line` | `user:$apr1$…` / `user:{SHA}…` (dosya formatı) | 2.1-C |

`router-openwrt.yaml` ek: `uci_secret_option`, `nvram_default_cred`.
`ipcam-generic.yaml` ek: `rtsp_password`, `onvif_cred`, `foscam`/`hikvision`
default hesap kalıpları.
