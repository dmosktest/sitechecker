import { localeNames, localeRecord, type Locale } from "./site-config";

export type SeoFaq = { q: string; a: string };

export type SeoCopy = {
  title: string;
  description: string;
  heading: string;
  leadHtml: string;
  benefitsTitle: string;
  benefits: string[];
  howTitle: string;
  howSteps: string[];
  strongTitle: string;
  strongLead: string;
  strongTips: string[];
  usesTitle: string;
  uses: string[];
  faqTitle: string;
  faq: SeoFaq[];
  appName: string;
  tipsLabel: string;
};

type SeoBody = Omit<SeoCopy, "title" | "description" | "heading" | "leadHtml">;

const titles = localeNames({
  ru: "sitechecker — проверка безопасности сайта",
  en: "sitechecker — website security baseline check",
  zh: "sitechecker — 网站基础安全检查",
  es: "sitechecker — comprobación básica de seguridad web",
  hi: "sitechecker — वेबसाइट सुरक्षा जाँच",
  ar: "sitechecker — فحص أمان أساسي للموقع",
  bn: "sitechecker — ওয়েবসাইট নিরাপত্তা পরীক্ষা",
  pt: "sitechecker — verificação básica de segurança do site",
  fr: "sitechecker — contrôle de sécurité de base d’un site",
  de: "sitechecker — Basis-Sicherheitscheck für Websites",
  ja: "sitechecker — サイトの基本セキュリティ検査",
  id: "sitechecker — pemeriksaan keamanan dasar situs",
  pa: "sitechecker — ਵੈੱਬਸਾਈਟ ਸੁਰੱਖਿਆ ਜਾਂਚ",
  jv: "sitechecker — pamriksan keamanan dhasar situs",
  te: "sitechecker — వెబ్‌సైట్ భద్రతా తనిఖీ",
  tr: "sitechecker — site güvenlik temel kontrolü",
  ko: "sitechecker — 웹사이트 기본 보안 검사",
  mr: "sitechecker — वेबसाइट सुरक्षा तपासणी",
  vi: "sitechecker — kiểm tra bảo mật cơ bản cho website",
  ta: "sitechecker — இணையதள பாதுகாப்பு சரிபார்ப்பு",
  it: "sitechecker — controllo di sicurezza di base del sito",
  fa: "sitechecker — بررسی پایهٔ امنیت وب‌سایت",
  tlh: "sitechecker — jan Hub chov",
});

const descriptions = localeNames({
  ru: "Пассивная проверка заголовков, TLS, cookie, DNS и почты за минуту. Оценка A–F и готовые правки для nginx, Apache, Traefik и Caddy. Без регистрации.",
  en: "Passive check of headers, TLS, cookies, DNS and mail in about a minute. Grade A–F plus copy-paste nginx, Apache, Traefik and Caddy fixes. No signup.",
  zh: "约一分钟完成响应头、TLS、Cookie、DNS 与邮件的被动检查。A–F 评级及可复制的 nginx/Apache/Traefik/Caddy 修复。无需注册。",
  es: "Comprobación pasiva de cabeceras, TLS, cookies, DNS y correo en un minuto. Nota A–F y correcciones para nginx, Apache, Traefik y Caddy. Sin registro.",
  hi: "लगभग एक मिनट में हेडर, TLS, कुकी, DNS और मेल की निष्क्रिय जाँच। ग्रेड A–F तथा nginx/Apache/Traefik/Caddy सुधार। बिना साइनअप।",
  ar: "فحص سلبي للعناوين وTLS وملفات الارتباط وDNS والبريد خلال دقيقة. درجة A–F وإصلاحات nginx وApache وTraefik وCaddy. بلا تسجيل.",
  bn: "প্রায় এক মিনিটে হেডার, TLS, কুকি, DNS ও মেইলের প্যাসিভ পরীক্ষা। গ্রেড A–F এবং nginx/Apache/Traefik/Caddy সংশোধন। রেজিস্ট্রেশন নেই।",
  pt: "Verificação passiva de cabeçalhos, TLS, cookies, DNS e correio em cerca de um minuto. Nota A–F e correções nginx/Apache/Traefik/Caddy. Sem registo.",
  fr: "Contrôle passif des en-têtes, TLS, cookies, DNS et mail en une minute. Note A–F et correctifs nginx/Apache/Traefik/Caddy. Sans inscription.",
  de: "Passiver Check von Headern, TLS, Cookies, DNS und Mail in etwa einer Minute. Note A–F und nginx/Apache/Traefik/Caddy-Fixes. Ohne Registrierung.",
  ja: "ヘッダー・TLS・Cookie・DNS・メールを約1分で受動検査。評価A–Fとnginx/Apache/Traefik/Caddyの修正例。登録不要。",
  id: "Pemeriksaan pasif header, TLS, cookie, DNS, dan email sekitar satu menit. Nilai A–F serta perbaikan nginx/Apache/Traefik/Caddy. Tanpa daftar.",
  pa: "ਲਗਭਗ ਇੱਕ ਮਿੰਟ ਵਿੱਚ ਹੈਡਰ, TLS, ਕੁਕੀਜ਼, DNS ਅਤੇ ਮੇਲ ਦੀ ਪੈਸਿਵ ਜਾਂਚ। ਗ੍ਰੇਡ A–F ਅਤੇ nginx/Apache/Traefik/Caddy ਫਿਕਸ। ਬਿਨਾਂ ਸਾਈਨਅੱਪ।",
  jv: "Pamriksan pasif header, TLS, cookie, DNS lan email watara sedhela. Nilai A–F lan perbaikan nginx/Apache/Traefik/Caddy. Tanpa ndaftar.",
  te: "హెడర్లు, TLS, కుకీలు, DNS, మెయిల్‌ను ఒక నిమిషంలో పాసివ్ చెక్. గ్రేడ్ A–F మరియు nginx/Apache/Traefik/Caddy ఫిక్స్. సైనప్ లేదు.",
  tr: "Başlıklar, TLS, çerezler, DNS ve posta için yaklaşık bir dakikada pasif kontrol. A–F notu ve nginx/Apache/Traefik/Caddy düzeltmeleri. Kayıt yok.",
  ko: "헤더·TLS·쿠키·DNS·메일을 약 1분 만에 수동 검사. A–F 등급과 nginx/Apache/Traefik/Caddy 수정안. 가입 불필요.",
  mr: "हेडर, TLS, कुकी, DNS आणि मेलची सुमारे एका मिनिटात निष्क्रिय तपासणी. ग्रेड A–F आणि nginx/Apache/Traefik/Caddy सुधार. नोंदणी नाही.",
  vi: "Kiểm tra thụ động header, TLS, cookie, DNS và thư trong khoảng một phút. Điểm A–F và bản sửa nginx/Apache/Traefik/Caddy. Không cần đăng ký.",
  ta: "தலைப்புகள், TLS, குக்கிகள், DNS, அஞ்சல் — சுமார் ஒரு நிமிடத்தில் செயலற்ற சரிபார்ப்பு. A–F தரமும் nginx/Apache/Traefik/Caddy திருத்தங்களும். பதிவு இல்லை.",
  it: "Controllo passivo di intestazioni, TLS, cookie, DNS e posta in circa un minuto. Voto A–F e fix nginx/Apache/Traefik/Caddy. Senza registrazione.",
  fa: "بررسی غیرفعال هدر، TLS، کوکی، DNS و ایمیل در حدود یک دقیقه. نمره A–F و اصلاحات nginx/Apache/Traefik/Caddy. بدون ثبت‌نام.",
  tlh: "headers TLS cookies DNS qIrgh chov. A–F. nginx Apache Traefik Caddy. yIje'Qo'.",
});

const headings = localeNames({
  ru: "Проверка безопасности сайта",
  en: "Website security check",
  zh: "网站安全检查",
  es: "Comprobación de seguridad del sitio",
  hi: "वेबसाइट सुरक्षा जाँच",
  ar: "فحص أمان الموقع",
  bn: "ওয়েবসাইট নিরাপত্তা পরীক্ষা",
  pt: "Verificação de segurança do site",
  fr: "Contrôle de sécurité du site",
  de: "Website-Sicherheitscheck",
  ja: "サイトのセキュリティ検査",
  id: "Pemeriksaan keamanan situs",
  pa: "ਵੈੱਬਸਾਈਟ ਸੁਰੱਖਿਆ ਜਾਂਚ",
  jv: "Pamriksan keamanan situs",
  te: "వెబ్‌సైట్ భద్రతా తనిఖీ",
  tr: "Site güvenlik kontrolü",
  ko: "웹사이트 보안 검사",
  mr: "वेबसाइट सुरक्षा तपासणी",
  vi: "Kiểm tra bảo mật website",
  ta: "இணையதள பாதுகாப்பு சரிபார்ப்பு",
  it: "Controllo di sicurezza del sito",
  fa: "بررسی امنیت وب‌سایت",
  tlh: "jan Hub chov",
});

const leads = localeNames({
  ru: "Введите домен — за минуту получите оценку A–F, список проблем и готовые правки для nginx, Apache, Traefik и Caddy. Только пассивные запросы, без атак.",
  en: "Enter a domain — get an A–F grade, findings, and copy-paste nginx/Apache/Traefik/Caddy fixes in about a minute. Passive requests only, no attacks.",
  zh: "输入域名，约一分钟获得 A–F 评级、问题列表以及可复制的 nginx/Apache/Traefik/Caddy 修复。仅被动请求，无攻击。",
  es: "Introduzca un dominio: nota A–F, hallazgos y correcciones nginx/Apache/Traefik/Caddy en un minuto. Solo peticiones pasivas, sin ataques.",
  hi: "डोमेन दर्ज करें — लगभग एक मिनट में ग्रेड A–F, निष्कर्ष और nginx/Apache/Traefik/Caddy सुधार। केवल निष्क्रिय अनुरोध, कोई हमला नहीं।",
  ar: "أدخل نطاقًا واحصل على درجة A–F والمشكلات وإصلاحات nginx/Apache/Traefik/Caddy خلال دقيقة. طلبات سلبية فقط بلا هجمات.",
  bn: "ডোমেইন লিখুন — প্রায় এক মিনিটে গ্রেড A–F, ফলাফল ও nginx/Apache/Traefik/Caddy সংশোধন। শুধু প্যাসিভ অনুরোধ, কোনো আক্রমণ নয়।",
  pt: "Introduza um domínio — nota A–F, achados e correções nginx/Apache/Traefik/Caddy em cerca de um minuto. Apenas pedidos passivos, sem ataques.",
  fr: "Saisissez un domaine — note A–F, constats et correctifs nginx/Apache/Traefik/Caddy en une minute. Requêtes passives uniquement, sans attaques.",
  de: "Domain eingeben — Note A–F, Befunde und nginx/Apache/Traefik/Caddy-Fixes in etwa einer Minute. Nur passive Anfragen, keine Angriffe.",
  ja: "ドメインを入力 — 約1分で評価A–F、所見、nginx/Apache/Traefik/Caddyの修正例。受動リクエストのみ、攻撃なし。",
  id: "Masukkan domain — nilai A–F, temuan, dan perbaikan nginx/Apache/Traefik/Caddy dalam sekitar satu menit. Hanya permintaan pasif, tanpa serangan.",
  pa: "ਡੋਮੇਨ ਦਰਜ ਕਰੋ — ਲਗਭਗ ਇੱਕ ਮਿੰਟ ਵਿੱਚ ਗ੍ਰੇਡ A–F, ਨਤੀਜੇ ਅਤੇ nginx/Apache/Traefik/Caddy ਫਿਕਸ। ਸਿਰਫ਼ ਪੈਸਿਵ ਬੇਨਤੀਆਂ, ਕੋਈ ਹਮਲਾ ਨਹੀਂ।",
  jv: "Lebokake domain — nilai A–F, temuan, lan perbaikan nginx/Apache/Traefik/Caddy watara sedhela. Mung panjalukan pasif, tanpa serangan.",
  te: "డొమైన్ ఇవ్వండి — ఒక నిమిషంలో గ్రేడ్ A–F, ఫలితాలు, nginx/Apache/Traefik/Caddy ఫిక్స్. కేవలం పాసివ్ అభ్యర్థనలు, దాడులు లేవు.",
  tr: "Alan adı girin — yaklaşık bir dakikada A–F notu, bulgular ve nginx/Apache/Traefik/Caddy düzeltmeleri. Yalnızca pasif istekler, saldırı yok.",
  ko: "도메인을 입력하세요 — 약 1분 만에 A–F 등급, 결과, nginx/Apache/Traefik/Caddy 수정안. 수동 요청만, 공격 없음.",
  mr: "डोमेन टाका — सुमारे एका मिनिटात ग्रेड A–F, निष्कर्ष आणि nginx/Apache/Traefik/Caddy सुधार. फक्त निष्क्रिय विनंत्या, हल्ले नाहीत.",
  vi: "Nhập tên miền — trong khoảng một phút có điểm A–F, phát hiện và bản sửa nginx/Apache/Traefik/Caddy. Chỉ yêu cầu thụ động, không tấn công.",
  ta: "டொமைனை உள்ளிடுங்கள் — சுமார் ஒரு நிமிடத்தில் A–F தரம், கண்டுபிடிப்புகள், nginx/Apache/Traefik/Caddy திருத்தங்கள். செயலற்ற கோரிக்கைகள் மட்டும், தாக்குதல் இல்லை.",
  it: "Inserisci un dominio — voto A–F, risultati e fix nginx/Apache/Traefik/Caddy in circa un minuto. Solo richieste passive, senza attacchi.",
  fa: "دامنه را وارد کنید — در حدود یک دقیقه نمره A–F، یافته‌ها و اصلاحات nginx/Apache/Traefik/Caddy. فقط درخواست غیرفعال، بدون حمله.",
  tlh: "Domain yIje'. A–F. nginx Apache Traefik Caddy. HIvQo'.",
});

const enBody: SeoBody = {
  benefitsTitle: "Why use sitechecker",
  benefits: [
    "Twenty-nine passive baseline checks: security headers, TLS, cookies, CMS hints, DNS and mail.",
    "Plain-language risk notes and copy-paste fixes for nginx, Apache, Traefik and Caddy.",
    "A–F grade with the three highest-impact fixes called out first.",
    "No account required for a one-off scan.",
  ],
  howTitle: "How it works",
  howSteps: [
    "Enter the domain and start the check.",
    "Workers fetch only with GET/HEAD under SSRF safeguards.",
    "Review the grade, group summary, and each finding with evidence.",
    "Copy a fix for your stack and re-check after deploying.",
  ],
  strongTitle: "What we look at",
  strongLead: "The MVP covers level-1 hygiene that any visitor can observe — not penetration testing.",
  tipsLabel: "Tips",
  strongTips: [
    "Enable HSTS only after HTTPS works on every hostname you serve.",
    "Start CSP in Report-Only before enforcing.",
    "Add SPF and DMARC before sending production mail.",
  ],
  usesTitle: "Typical uses",
  uses: [
    "Pre-launch checklist for freelancers and small shops.",
    "Quick TLS and header sanity check for ops.",
    "Shareable JSON report for a client hand-off.",
  ],
  faqTitle: "FAQ",
  faq: [
    {
      q: "Does this mean my site is secure?",
      a: "No. The report is a passive baseline only and never claims the site is safe against attacks.",
    },
    {
      q: "Do you attack my site?",
      a: "No. We only send GET and HEAD requests, never forms, logins, or exploit payloads.",
    },
    {
      q: "How do I opt out?",
      a: "Publish DNS TXT _sitechecker-optout with value sitechecker-optout (or 1/true), or mention sitechecker-optout in security.txt.",
    },
    {
      q: "What is checked for free?",
      a: "Level-1 checks: headers, TLS, cookies, public software hints, DNS/mail, and security.txt.",
    },
  ],
  appName: "sitechecker",
};

const ruBody: SeoBody = {
  benefitsTitle: "Зачем sitechecker",
  benefits: [
    "29 пассивных проверок: заголовки, TLS, cookie, CMS, DNS и почта.",
    "Понятные риски и копируемые правки для nginx, Apache, Traefik и Caddy.",
    "Оценка A–F и три самых важных исправления сверху.",
    "Без регистрации для разовой проверки.",
  ],
  howTitle: "Как это работает",
  howSteps: [
    "Введите домен и запустите проверку.",
    "Воркер ходит только GET/HEAD с защитой от SSRF.",
    "Смотрите оценку, сводку по группам и доказательства.",
    "Скопируйте фикс под свой стек и проверьте снова.",
  ],
  strongTitle: "Что смотрим",
  strongLead: "MVP — гигиена уровня 1, которую видит любой посетитель, а не пентест.",
  tipsLabel: "Подсказки",
  strongTips: [
    "Включайте HSTS, когда HTTPS работает на всех хостах.",
    "CSP сначала в Report-Only, потом в боевой режим.",
    "Настройте SPF и DMARC до боевой почты.",
  ],
  usesTitle: "Кому полезно",
  uses: [
    "Чеклист перед сдачей сайта клиенту.",
    "Быстрая сверка TLS и заголовков для админов.",
    "JSON-отчёт для передачи заказчику.",
  ],
  faqTitle: "FAQ",
  faq: [
    {
      q: "Это значит, что сайт безопасен?",
      a: "Нет. Отчёт — только пассивная базовая проверка и не обещает защиту от атак.",
    },
    {
      q: "Вы атакуете сайт?",
      a: "Нет. Только GET и HEAD, без форм, логинов и эксплойтов.",
    },
    {
      q: "Как запретить проверки?",
      a: "DNS TXT _sitechecker-optout со значением sitechecker-optout (или 1/true), либо упоминание в security.txt.",
    },
    {
      q: "Что входит в бесплатную проверку?",
      a: "Уровень 1: заголовки, TLS, cookie, публичные признаки ПО, DNS/почта и security.txt.",
    },
  ],
  appName: "sitechecker",
};

function localizedBody(locale: Locale): SeoBody {
  if (locale === "ru") return ruBody;
  return enBody;
}

export const SEO_COPY: Record<Locale, SeoCopy> = localeRecord((locale) => {
  const body = localizedBody(locale);
  return {
    title: titles[locale],
    description: descriptions[locale],
    heading: headings[locale],
    leadHtml: leads[locale],
    ...body,
  };
});
