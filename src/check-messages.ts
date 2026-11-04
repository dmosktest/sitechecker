import type { Locale } from "./site-config";
import { localeNames } from "./site-config";

type Copy = Partial<Record<Locale, string>> & { en: string };

const checks: Record<string, { title: Copy; danger: Copy; fix?: Copy }> = {
  H1: {
    title: {
      en: "HSTS is missing or too weak",
      ru: "Нет HSTS или срок слишком короткий",
    },
    danger: {
      en: "Without a strong Strict-Transport-Security header, browsers may keep using plain HTTP after the first visit and open the door to interception.",
      ru: "Без нормального заголовка Strict-Transport-Security браузер может снова ходить по обычному HTTP и попасть под перехват трафика.",
    },
  },
  H2: {
    title: {
      en: "Content-Security-Policy is missing or too loose",
      ru: "Нет Content-Security-Policy или политика слишком мягкая",
    },
    danger: {
      en: "A missing or permissive CSP makes XSS and script injection much easier to exploit.",
      ru: "Без CSP или с unsafe-inline / * злоумышленнику проще внедрить свой скрипт на страницу (XSS).",
    },
  },
  H3: {
    title: {
      en: "Clickjacking protection is missing",
      ru: "Нет защиты от clickjacking",
    },
    danger: {
      en: "Without X-Frame-Options or CSP frame-ancestors the site can be embedded in a malicious iframe.",
      ru: "Без X-Frame-Options или frame-ancestors в CSP сайт можно встроить во вредоносный iframe и обмануть пользователя кликами.",
    },
  },
  H4: {
    title: {
      en: "MIME sniffing is not blocked",
      ru: "Не запрещён MIME-sniffing",
    },
    danger: {
      en: "Without X-Content-Type-Options: nosniff the browser may treat a file as a different type than the server intended.",
      ru: "Без X-Content-Type-Options: nosniff браузер может сам «угадать» тип файла и выполнить его не так, как задумал сервер.",
    },
  },
  H5: {
    title: {
      en: "Referrer-Policy is not set",
      ru: "Не задан Referrer-Policy",
    },
    danger: {
      en: "Full referrer URLs may leak internal paths or tokens to third-party sites.",
      ru: "В referrer могут уходить внутренние пути и токены на чужие сайты.",
    },
  },
  H6: {
    title: {
      en: "Permissions-Policy is not set",
      ru: "Не задан Permissions-Policy",
    },
    danger: {
      en: "Browser features like camera, mic or geolocation stay available to the page and embeds unless you restrict them.",
      ru: "Камера, микрофон и геолокация остаются доступны странице и встраиваемому коду, пока вы их явно не ограничили.",
    },
  },
  H7: {
    title: {
      en: "Server software versions are exposed",
      ru: "Светится версия серверного ПО",
    },
    danger: {
      en: "Version banners help attackers pick known exploits for your stack.",
      ru: "По версии в заголовках проще подобрать известный эксплойт под ваш стек.",
    },
  },
  H8: {
    title: {
      en: "Dangerous CORS combination",
      ru: "Опасная комбинация CORS",
    },
    danger: {
      en: "Allow-Origin * together with credentials lets any site read authenticated responses.",
      ru: "Access-Control-Allow-Origin: * вместе с credentials позволяет любому сайту читать ответы от вашего имени.",
    },
  },
  T1: {
    title: {
      en: "HTTP does not redirect to HTTPS",
      ru: "HTTP не перенаправляет на HTTPS",
    },
    danger: {
      en: "Users who open http:// can stay on an unencrypted connection.",
      ru: "Кто открыл http://, может остаться на незашифрованном соединении.",
    },
  },
  T2: {
    title: {
      en: "HTTPS is unavailable or broken",
      ru: "HTTPS недоступен или сломан",
    },
    danger: {
      en: "Without working TLS traffic can be read or altered on the path.",
      ru: "Без рабочего TLS трафик можно прочитать или подменить по пути.",
    },
  },
  T3: {
    title: {
      en: "TLS version is outdated",
      ru: "Устаревшая версия TLS",
    },
    danger: {
      en: "Old TLS protocols have known weaknesses; prefer TLS 1.2+.",
      ru: "Старые версии TLS уязвимы; нужен как минимум TLS 1.2.",
    },
  },
  T4: {
    title: {
      en: "Weak TLS ciphers detected",
      ru: "Слабые шифры TLS",
    },
    danger: {
      en: "Weak cipher suites make interception or downgrade attacks easier.",
      ru: "Слабые наборы шифров упрощают перехват и атаки с понижением уровня защиты.",
    },
  },
  T5: {
    title: {
      en: "Mixed content on the page",
      ru: "Смешанный контент на странице",
    },
    danger: {
      en: "HTTP scripts or assets on an HTTPS page can be swapped by an attacker on the network.",
      ru: "HTTP-скрипты или ресурсы на HTTPS-странице можно подменить в сети.",
    },
  },
  T6: {
    title: {
      en: "HTTP/2 is not offered",
      ru: "HTTP/2 не предлагается",
    },
    danger: {
      en: "Not a direct security hole, but modern HTTPS stacks usually enable HTTP/2 for performance and current defaults.",
      ru: "Это не дыра в безопасности, но современный HTTPS-стек обычно включает HTTP/2.",
    },
  },
  C1: {
    title: {
      en: "Cookies without the Secure flag",
      ru: "Cookie без флага Secure",
    },
    danger: {
      en: "Session cookies without Secure can be sent over plain HTTP and stolen.",
      ru: "Сессионные cookie без Secure могут уйти по обычному HTTP и быть украдены.",
    },
    fix: {
      en: "Mark session cookies Secure in the application cookie API when serving over HTTPS.",
      ru: "В приложении пометьте сессионные cookie флагом Secure, если сайт отдаётся по HTTPS.",
    },
  },
  C2: {
    title: {
      en: "Cookies without HttpOnly",
      ru: "Cookie без HttpOnly",
    },
    danger: {
      en: "Without HttpOnly any XSS script can read session cookies from document.cookie.",
      ru: "Без HttpOnly любой XSS-скрипт может прочитать сессию через document.cookie.",
    },
    fix: {
      en: "Mark session cookies HttpOnly in the application cookie API.",
      ru: "В приложении пометьте сессионные cookie флагом HttpOnly.",
    },
  },
  C3: {
    title: {
      en: "Cookies without SameSite",
      ru: "Cookie без SameSite",
    },
    danger: {
      en: "Missing SameSite makes cross-site request forgery (CSRF) easier.",
      ru: "Без SameSite проще провести CSRF — чужой сайт отправит запрос от имени пользователя.",
    },
    fix: {
      en: "Add SameSite=Lax (or Strict) to cookies that do not need cross-site POSTs.",
      ru: "Добавьте SameSite=Lax (или Strict) cookie, которым не нужен cross-site POST.",
    },
  },
  C4: {
    title: {
      en: "Cookie name prefixes are unused",
      ru: "Не используются префиксы имён cookie",
    },
    danger: {
      en: "Prefixes like __Host- help lock cookies to a secure origin; optional hardening.",
      ru: "Префиксы вроде __Host- жёстче привязывают cookie к безопасному origin — дополнительное усиление.",
    },
  },
  F1: {
    title: {
      en: "Git repository is publicly readable",
      ru: "Репозиторий .git открыт снаружи",
    },
    danger: {
      en: "Anyone can download source, history and sometimes secrets from an exposed .git tree.",
      ru: "Из открытого .git можно скачать исходники, историю и иногда секреты.",
    },
    fix: {
      en: "Remove .git from the public document root; keep repositories outside the web tree.",
      ru: "Уберите .git из публичного document root; репозиторий держите вне веб-дерева.",
    },
  },
  F2: {
    title: {
      en: "Environment or config backups are reachable",
      ru: "Доступны бэкапы окружения или конфигов",
    },
    danger: {
      en: "Files like .env or wp-config.php.bak often contain database passwords and API keys.",
      ru: "В .env или wp-config.php.bak часто лежат пароли БД и ключи API.",
    },
    fix: {
      en: "Delete backup copies of secrets from the public tree; rotate any credentials that were exposed.",
      ru: "Удалите бэкапы секретов из публичного дерева и смените всё, что могло утечь.",
    },
  },
  F3: {
    title: {
      en: "Backup archives or SQL dumps are public",
      ru: "Публично лежат архивы или SQL-дампы",
    },
    danger: {
      en: "Downloadable dumps expose customer data and credentials in one click.",
      ru: "Скачиваемый дамп отдаёт данные клиентов и учётные данные одним кликом.",
    },
    fix: {
      en: "Remove database dumps and archives from publicly reachable directories.",
      ru: "Уберите дампы БД и архивы из каталогов, доступных из интернета.",
    },
  },
  F4: {
    title: {
      en: "Diagnostic pages are exposed",
      ru: "Открыты диагностические страницы",
    },
    danger: {
      en: "phpinfo and server-status leak versions, paths and configuration details useful for attacks.",
      ru: "phpinfo и server-status светят версии, пути и настройки, удобные для атаки.",
    },
    fix: {
      en: "Remove diagnostic scripts and restrict Apache/nginx status handlers to localhost.",
      ru: "Удалите phpinfo и ограничьте status-handlers nginx/Apache только localhost.",
    },
  },
  F5: {
    title: {
      en: "Directory listing is enabled",
      ru: "Включён листинг каталогов",
    },
    danger: {
      en: "Browsable folders reveal file names, backups and forgotten scripts.",
      ru: "Открытый Index of показывает имена файлов, бэкапы и забытые скрипты.",
    },
    fix: {
      en: "Turn off autoindex / Options Indexes on the web server.",
      ru: "Выключите autoindex / Options Indexes на веб-сервере.",
    },
  },
  F6: {
    title: {
      en: "Database admin panels look public",
      ru: "Похоже, открыты панели управления БД",
    },
    danger: {
      en: "phpMyAdmin or Adminer on the public Internet are a common takeover path.",
      ru: "phpMyAdmin или Adminer в открытом интернете — частый путь к захвату сайта.",
    },
    fix: {
      en: "Remove public DB admin tools or put them behind VPN, basic auth, and IP allowlists.",
      ru: "Уберите публичные панели БД или закройте их VPN, basic auth и allowlist по IP.",
    },
  },
  F7: {
    title: {
      en: "security.txt is missing",
      ru: "Нет файла security.txt",
    },
    danger: {
      en: "Researchers have no clear place to report vulnerabilities (RFC 9116).",
      ru: "Исследователям некуда официально сообщить о находке (RFC 9116).",
    },
    fix: {
      en: "Publish /.well-known/security.txt with Contact and Expires fields (RFC 9116).",
      ru: "Опубликуйте /.well-known/security.txt с полями Contact и Expires (RFC 9116).",
    },
  },
  S1: {
    title: {
      en: "Public technology fingerprint",
      ru: "Публичный отпечаток технологий",
    },
    danger: {
      en: "Visible CMS/JS stacks are not a vulnerability by themselves, but they guide reconnaissance.",
      ru: "Видимый CMS/JS сам по себе не дыра, но упрощает разведку атакующему.",
    },
  },
  S2: {
    title: {
      en: "Possibly outdated software",
      ru: "Возможно устаревшее ПО",
    },
    danger: {
      en: "Known old versions often have public CVEs — update if the signal matches your stack.",
      ru: "У старых версий часто есть публичные CVE — сверьте с вашим стеком и обновите.",
    },
  },
  S3: {
    title: {
      en: "Sensitive paths look exposed",
      ru: "Похоже, открыты чувствительные пути",
    },
    danger: {
      en: "Admin panels, backups or debug URLs reachable without auth raise takeover risk.",
      ru: "Админки, бэкапы или debug-URL без защиты повышают риск захвата сайта.",
    },
  },
  S4: {
    title: {
      en: "Subresource Integrity is missing",
      ru: "Нет Subresource Integrity",
    },
    danger: {
      en: "Third-party scripts without SRI can change silently if the CDN is compromised.",
      ru: "Чужие скрипты без SRI могут незаметно измениться, если CDN скомпрометирован.",
    },
  },
  D1: {
    title: {
      en: "SPF record is missing or unsafe",
      ru: "SPF отсутствует или небезопасен",
    },
    danger: {
      en: "SPF lists which servers may send mail as your domain. Without it (or with +all), attackers can forge password-reset and invoice emails that look like they come from the same domain as your website — users trust that name.",
      ru: "SPF задаёт, каким серверам можно слать почту от вашего домена. Без записи или с +all проще подделать «сброс пароля» и счета с того же домена, что у сайта — люди доверяют этому имени.",
    },
    fix: {
      en: "Add a TXT SPF record on {domain}, e.g. v=spf1 -all (avoid +all). If you send mail, use your provider include and end with -all.",
      ru: "Добавьте TXT SPF на {domain}, например: v=spf1 -all (без +all). Если шлёте почту — include провайдера и в конце -all.",
      de: "TXT-SPF für {domain} setzen, z. B. v=spf1 -all (kein +all). Bei Versand: include des Providers und -all am Ende.",
      fr: "Ajoutez un TXT SPF sur {domain}, p.ex. v=spf1 -all (évitez +all). Si vous envoyez du mail : include du fournisseur puis -all.",
      es: "Añada un TXT SPF en {domain}, p. ej. v=spf1 -all (evite +all). Si envía correo: include del proveedor y -all al final.",
      zh: "在 {domain} 添加 TXT SPF，例如 v=spf1 -all（不要用 +all）。若发信：用服务商 include，并以 -all 结尾。",
      ja: "{domain} に TXT SPF を追加（例: v=spf1 -all、+all は不可）。送信する場合はプロバイダの include と末尾 -all。",
      ko: "{domain}에 TXT SPF를 추가하세요. 예: v=spf1 -all(+all 금지). 메일을 보내면 제공자 include와 끝의 -all.",
      pt: "Adicione TXT SPF em {domain}, ex.: v=spf1 -all (evite +all). Se enviar correio: include do fornecedor e -all no fim.",
      it: "Aggiungi TXT SPF su {domain}, es. v=spf1 -all (niente +all). Se invii posta: include del provider e -all in coda.",
      tr: "{domain} için TXT SPF ekleyin, örn. v=spf1 -all (+all kullanmayın). Posta gönderiyorsanız sağlayıcı include ve sonda -all.",
      ar: "أضف سجل TXT لـ SPF على {domain} مثل v=spf1 -all (تجنب +all). إن أرسلت بريداً: include للمزوّد ثم -all.",
      hi: "{domain} पर TXT SPF जोड़ें, जैसे v=spf1 -all (+all न रखें)। मेल भेजते हों तो प्रदाता include और अंत में -all।",
      fa: "روی {domain} رکورد TXT SPF بگذارید، مثلاً v=spf1 -all (بدون +all). اگر نامه می‌فرستید include سرویس‌دهنده و در پایان -all.",
    },
  },
  D2: {
    title: {
      en: "DKIM selectors not found",
      ru: "Селекторы DKIM не найдены",
    },
    danger: {
      en: "DKIM signs outbound mail so receivers can tell it really came from you. Without a signature, phishing that abuses your brand (the same domain users see on the site) is harder to filter — login alerts and resets look less trustworthy.",
      ru: "DKIM подписывает исходящую почту, чтобы получатель видел: письмо действительно ваше. Без подписи фишинг под бренд сайта (тот же домен) сложнее отсеять — «вход» и «сброс пароля» перестают быть надёжным сигналом.",
    },
  },
  D3: {
    title: {
      en: "DMARC is missing or too weak",
      ru: "DMARC отсутствует или слишком мягкий",
    },
    danger: {
      en: "DMARC tells mail providers what to do when SPF/DKIM fail. Without p=quarantine or p=reject, forged mail from your domain still reaches inboxes — phishing against site users and brand reputation, not “just email hygiene”.",
      ru: "DMARC говорит почтовым сервисам, что делать, если SPF/DKIM не сошлись. Без p=quarantine или p=reject поддельные письма с вашего домена всё ещё доходят — это фишинг пользователей сайта и удар по бренду, а не «просто почтовая гигиена».",
    },
    fix: {
      en: "Add a TXT record on _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      ru: "Добавьте TXT на _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      de: "TXT auf _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      fr: "Ajoutez un TXT sur _dmarc.{domain} : v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      es: "Añada TXT en _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      zh: "在 _dmarc.{domain} 添加 TXT：v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      ja: "_dmarc.{domain} に TXT を追加：v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      ko: "_dmarc.{domain}에 TXT 추가: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      pt: "Adicione TXT em _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      it: "Aggiungi TXT su _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      tr: "_dmarc.{domain} için TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      ar: "أضف TXT على _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      hi: "_dmarc.{domain} पर TXT जोड़ें: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
      fa: "روی _dmarc.{domain} رکورد TXT بگذارید: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
    },
  },
  D4: {
    title: {
      en: "DNSSEC status",
      ru: "Статус DNSSEC",
    },
    danger: {
      en: "DNSSEC helps stop DNS spoofing; absence is common but worth noting for high-risk domains.",
      ru: "DNSSEC мешает подмене DNS; его часто нет, но для важных доменов стоит рассмотреть.",
    },
  },
  D5: {
    title: {
      en: "CAA records",
      ru: "Записи CAA",
    },
    danger: {
      en: "CAA limits which CAs may issue certificates for your domain.",
      ru: "CAA ограничивает, какие удостоверяющие центры могут выпускать сертификаты на ваш домен.",
    },
  },
  D6: {
    title: {
      en: "Internal or risky DNS targets",
      ru: "Внутренние или рискованные цели в DNS",
    },
    danger: {
      en: "DNS pointing at private or metadata addresses can enable SSRF-style abuse of your infra.",
      ru: "DNS на частные или metadata-адреса облегчает SSRF-подобные атаки на вашу инфраструктуру.",
    },
  },
};

export function checkTitle(locale: Locale, id: string): string {
  const row = checks[id];
  if (!row) return id;
  return localeNames(row.title)[locale] || row.title.en;
}

export function checkDanger(locale: Locale, id: string): string {
  const row = checks[id];
  if (!row) return "";
  return localeNames(row.danger)[locale] || row.danger.en;
}

const dnsFixIds = new Set(["D1", "D3"]);

export function isDnsFix(id: string): boolean {
  return dnsFixIds.has(id);
}

export function checkFix(locale: Locale, id: string, domain: string): string {
  const row = checks[id];
  if (!row?.fix) return "";
  const host = domain.trim() || "example.com";
  return (localeNames(row.fix)[locale] || row.fix.en).split("{domain}").join(host);
}
