import type { Locale } from "./site-config";
import { localeNames } from "./site-config";

type Copy = Partial<Record<Locale, string>> & { en: string };

const checks: Record<string, { title: Copy; danger: Copy }> = {
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
  F7: {
    title: {
      en: "security.txt is missing",
      ru: "Нет файла security.txt",
    },
    danger: {
      en: "Researchers have no clear place to report vulnerabilities (RFC 9116).",
      ru: "Исследователям некуда официально сообщить о находке (RFC 9116).",
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
      en: "Without a proper SPF record anyone can more easily send mail that looks like yours.",
      ru: "Без нормального SPF проще слать письма якобы от вашего домена.",
    },
  },
  D2: {
    title: {
      en: "DKIM selectors not found",
      ru: "Селекторы DKIM не найдены",
    },
    danger: {
      en: "DKIM signs outbound mail; missing selectors may mean signing is not set up (or uses uncommon names).",
      ru: "DKIM подписывает исходящую почту; нет селекторов — подпись, скорее всего, не настроена.",
    },
  },
  D3: {
    title: {
      en: "DMARC is missing or too weak",
      ru: "DMARC отсутствует или слишком мягкий",
    },
    danger: {
      en: "Without DMARC policy receivers do not know whether to reject forged mail from your domain.",
      ru: "Без политики DMARC получатели не знают, отклонять ли поддельные письма с вашего домена.",
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
