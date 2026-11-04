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
  ru: "sitechecker — проверка безопасности сайта (уровни 1 и 2)",
  en: "sitechecker — website security check (levels 1 & 2)",
  zh: "sitechecker — 网站安全检查（一级与二级）",
  es: "sitechecker — comprobación de seguridad web (niveles 1 y 2)",
  hi: "sitechecker — वेबसाइट सुरक्षा जाँच (स्तर 1 और 2)",
  ar: "sitechecker — فحص أمان الموقع (المستويان 1 و2)",
  bn: "sitechecker — ওয়েবসাইট নিরাপত্তা পরীক্ষা (লেভেল ১ ও ২)",
  pt: "sitechecker — verificação de segurança do site (níveis 1 e 2)",
  fr: "sitechecker — contrôle de sécurité du site (niveaux 1 et 2)",
  de: "sitechecker — Website-Sicherheitscheck (Stufen 1 und 2)",
  ja: "sitechecker — サイトセキュリティ検査（レベル1・2）",
  id: "sitechecker — pemeriksaan keamanan situs (level 1 & 2)",
  pa: "sitechecker — ਵੈੱਬਸਾਈਟ ਸੁਰੱਖਿਆ ਜਾਂਚ (ਪੱਧਰ 1 ਅਤੇ 2)",
  jv: "sitechecker — pamriksan keamanan situs (level 1 & 2)",
  te: "sitechecker — వెబ్‌సైట్ భద్రతా తనిఖీ (స్థాయి 1 & 2)",
  tr: "sitechecker — site güvenlik kontrolü (seviye 1 ve 2)",
  ko: "sitechecker — 웹사이트 보안 검사(레벨 1·2)",
  mr: "sitechecker — वेबसाइट सुरक्षा तपासणी (स्तर १ आणि २)",
  vi: "sitechecker — kiểm tra bảo mật website (cấp 1 và 2)",
  ta: "sitechecker — இணையதள பாதுகாப்பு சரிபார்ப்பு (நிலை 1 & 2)",
  it: "sitechecker — controllo di sicurezza del sito (livelli 1 e 2)",
  fa: "sitechecker — بررسی امنیت وب‌سایت (سطح ۱ و ۲)",
  tlh: "sitechecker — jan Hub chov (1 2)",
});

const descriptions = localeNames({
  ru: "Пассивная проверка сайта за минуту: уровень 1 для всех, уровень 2 после подтверждения владения. Оценка A–F, живой ход, правки для nginx, Apache, Traefik, Caddy, Cloudflare и WordPress, ТЗ для ИИ. Без регистрации.",
  en: "Passive site check in about a minute: level 1 for everyone, level 2 after ownership proof. A–F grade, live progress, fixes for nginx, Apache, Traefik, Caddy, Cloudflare and WordPress, plus an AI brief. No signup.",
  zh: "约一分钟被动检查：人人可用的一级；确认所有权后启用二级。A–F 评级、实时进度，以及 nginx/Apache/Traefik/Caddy/Cloudflare/WordPress 修复与 AI 任务说明。无需注册。",
  es: "Comprobación pasiva en un minuto: nivel 1 para todos, nivel 2 tras demostrar propiedad. Nota A–F, progreso en vivo, correcciones nginx/Apache/Traefik/Caddy/Cloudflare/WordPress y brief para IA. Sin registro.",
  hi: "लगभग एक मिनट में निष्क्रिय जाँच: स्तर 1 सबके लिए, स्वामित्व पुष्टि के बाद स्तर 2। ग्रेड A–F, लाइव प्रगति, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress सुधार और AI ब्रीफ। बिना साइनअप।",
  ar: "فحص سلبي خلال دقيقة: المستوى 1 للجميع والمستوى 2 بعد إثبات الملكية. درجة A–F وتقدّم مباشر وإصلاحات nginx وApache وTraefik وCaddy وCloudflare وWordPress وموجز للذكاء الاصطناعي. بلا تسجيل.",
  bn: "প্রায় এক মিনিটে প্যাসিভ পরীক্ষা: সবার জন্য লেভেল ১, মালিকানা প্রমাণের পর লেভেল ২। গ্রেড A–F, লাইভ অগ্রগতি, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress সংশোধন ও AI ব্রিফ। রেজিস্ট্রেশন নেই।",
  pt: "Verificação passiva em cerca de um minuto: nível 1 para todos, nível 2 após prova de propriedade. Nota A–F, progresso ao vivo, correções nginx/Apache/Traefik/Caddy/Cloudflare/WordPress e brief para IA. Sem registo.",
  fr: "Contrôle passif en une minute : niveau 1 pour tous, niveau 2 après preuve de propriété. Note A–F, progression en direct, correctifs nginx/Apache/Traefik/Caddy/Cloudflare/WordPress et brief IA. Sans inscription.",
  de: "Passiver Check in etwa einer Minute: Stufe 1 für alle, Stufe 2 nach Besitz-Nachweis. Note A–F, Live-Fortschritt, Fixes für nginx/Apache/Traefik/Caddy/Cloudflare/WordPress und KI-Briefing. Ohne Registrierung.",
  ja: "約1分の受動検査。レベル1は誰でも、レベル2は所有確認後。評価A–F、進捗表示、nginx/Apache/Traefik/Caddy/Cloudflare/WordPressの修正例とAI向け指示。登録不要。",
  id: "Pemeriksaan pasif sekitar satu menit: level 1 untuk semua, level 2 setelah bukti kepemilikan. Nilai A–F, progres langsung, perbaikan nginx/Apache/Traefik/Caddy/Cloudflare/WordPress, plus brief AI. Tanpa daftar.",
  pa: "ਲਗਭਗ ਇੱਕ ਮਿੰਟ ਵਿੱਚ ਪੈਸਿਵ ਜਾਂਚ: ਪੱਧਰ 1 ਸਭ ਲਈ, ਮਾਲਕੀ ਤੋਂ ਬਾਅਦ ਪੱਧਰ 2। ਗ੍ਰੇਡ A–F, ਲਾਈਵ ਤਰੱਕੀ, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress ਫਿਕਸ ਅਤੇ AI ਬ੍ਰੀਫ। ਬਿਨਾਂ ਸਾਈਨਅੱਪ।",
  jv: "Pamriksan pasif watara sedhela: level 1 kanggo kabeh, level 2 sawise bukti kepemilikan. Nilai A–F, progres langsung, perbaikan nginx/Apache/Traefik/Caddy/Cloudflare/WordPress lan brief AI. Tanpa ndaftar.",
  te: "ఒక నిమిషంలో పాసివ్ చెక్: స్థాయి 1 అందరికీ, యాజమాన్యం నిర్ధారణ తర్వాత స్థాయి 2. గ్రేడ్ A–F, లైవ్ ప్రోగ్రెస్, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress ఫిక్స్ మరియు AI బ్రీఫ్. సైనప్ లేదు.",
  tr: "Yaklaşık bir dakikada pasif kontrol: seviye 1 herkese açık, seviye 2 sahiplik kanıtından sonra. A–F notu, canlı ilerleme, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress düzeltmeleri ve YZ brief. Kayıt yok.",
  ko: "약 1분 수동 검사: 레벨 1은 누구나, 레벨 2는 소유 확인 후. A–F 등급, 실시간 진행, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress 수정안과 AI 브리프. 가입 불필요.",
  mr: "सुमारे एका मिनिटात निष्क्रिय तपासणी: स्तर १ सर्वांसाठी, मालकी सिद्धीनंतर स्तर २. ग्रेड A–F, लाइव्ह प्रगती, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress सुधारणा आणि AI ब्रीफ. नोंदणी नाही.",
  vi: "Kiểm tra thụ động trong khoảng một phút: cấp 1 cho mọi người, cấp 2 sau xác minh quyền sở hữu. Điểm A–F, tiến trình trực tiếp, bản sửa nginx/Apache/Traefik/Caddy/Cloudflare/WordPress và brief AI. Không cần đăng ký.",
  ta: "சுமார் ஒரு நிமிடத்தில் செயலற்ற சரிபார்ப்பு: நிலை 1 அனைவருக்கும், உரிமை உறுதிக்குப் பின் நிலை 2. A–F தரம், நேரடி முன்னேற்றம், nginx/Apache/Traefik/Caddy/Cloudflare/WordPress திருத்தங்கள் மற்றும் AI சுருக்கம். பதிவு இல்லை.",
  it: "Controllo passivo in circa un minuto: livello 1 per tutti, livello 2 dopo prova di proprietà. Voto A–F, avanzamento live, fix nginx/Apache/Traefik/Caddy/Cloudflare/WordPress e brief per IA. Senza registrazione.",
  fa: "بررسی غیرفعال در حدود یک دقیقه: سطح ۱ برای همه، سطح ۲ پس از اثبات مالکیت. نمره A–F، پیشرفت زنده، اصلاحات nginx/Apache/Traefik/Caddy/Cloudflare/WordPress و خلاصه برای هوش مصنوعی. بدون ثبت‌نام.",
  tlh: "cha' tup chov. 1 Hoch. 2 Dom. A–F. nginx Apache Traefik Caddy Cloudflare WordPress. AI. yIje'Qo'.",
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
  ru: "Введите домен — за минуту получите оценку A–F, живой ход проверки и копируемые правки для nginx, Apache, Traefik, Caddy, Cloudflare и WordPress. После подтверждения владения (DNS, файл или meta) доступен уровень 2: .git, .env, бэкапы, phpinfo, листинг и админки БД. Только пассивные GET/HEAD, без атак. Можно скачать ТЗ для ИИ.",
  en: "Enter a domain — in about a minute get an A–F grade, live progress, and copy-paste fixes for nginx, Apache, Traefik, Caddy, Cloudflare and WordPress. After ownership proof (DNS, file or meta) unlock level 2: .git, .env, backups, phpinfo, directory listings and DB admin panels. Passive GET/HEAD only, no attacks. Download an AI remediation brief when done.",
  zh: "输入域名，约一分钟获得 A–F 评级、实时进度，以及可复制的 nginx/Apache/Traefik/Caddy/Cloudflare/WordPress 修复。确认所有权（DNS、文件或 meta）后启用二级：.git、.env、备份、phpinfo、目录列表与数据库管理面板。仅被动 GET/HEAD，无攻击。完成后可下载 AI 修复说明。",
  es: "Introduzca un dominio: en un minuto nota A–F, progreso en vivo y correcciones para nginx, Apache, Traefik, Caddy, Cloudflare y WordPress. Tras demostrar propiedad (DNS, archivo o meta) desbloquea el nivel 2: .git, .env, copias, phpinfo, listados y paneles de BD. Solo GET/HEAD pasivos. Puede descargar un brief para IA.",
  hi: "डोमेन दर्ज करें — लगभग एक मिनट में ग्रेड A–F, लाइव प्रगति और nginx/Apache/Traefik/Caddy/Cloudflare/WordPress सुधार। स्वामित्व (DNS, फ़ाइल या meta) के बाद स्तर 2: .git, .env, बैकअप, phpinfo, लिस्टिंग और DB एडमिन। केवल निष्क्रिय GET/HEAD। AI ब्रीफ डाउनलोड करें।",
  ar: "أدخل نطاقًا واحصل خلال دقيقة على درجة A–F وتقدّم مباشر وإصلاحات nginx وApache وTraefik وCaddy وCloudflare وWordPress. بعد إثبات الملكية (DNS أو ملف أو meta) يُفتح المستوى 2: .git و.env والنسخ وphpinfo والقوائم ولوحات قواعد البيانات. طلبات GET/HEAD سلبية فقط. يمكن تنزيل موجز للذكاء الاصطناعي.",
  bn: "ডোমেইন লিখুন — প্রায় এক মিনিটে গ্রেড A–F, লাইভ অগ্রগতি ও nginx/Apache/Traefik/Caddy/Cloudflare/WordPress সংশোধন। মালিকানা (DNS, ফাইল বা meta) প্রমাণের পর লেভেল ২: .git, .env, ব্যাকআপ, phpinfo, লিস্টিং ও DB অ্যাডমিন। শুধু প্যাসিভ GET/HEAD। AI ব্রিফ নামান।",
  pt: "Introduza um domínio — em cerca de um minuto nota A–F, progresso ao vivo e correções para nginx, Apache, Traefik, Caddy, Cloudflare e WordPress. Após prova de propriedade (DNS, ficheiro ou meta) desbloqueia o nível 2: .git, .env, backups, phpinfo, listagens e painéis de BD. Apenas GET/HEAD passivos. Descarregue um brief para IA.",
  fr: "Saisissez un domaine — en une minute note A–F, progression en direct et correctifs nginx, Apache, Traefik, Caddy, Cloudflare et WordPress. Après preuve de propriété (DNS, fichier ou meta), niveau 2 : .git, .env, sauvegardes, phpinfo, listings et panels BDD. Requêtes GET/HEAD passives uniquement. Téléchargez un brief IA.",
  de: "Domain eingeben — in etwa einer Minute Note A–F, Live-Fortschritt und Fixes für nginx, Apache, Traefik, Caddy, Cloudflare und WordPress. Nach Besitz-Nachweis (DNS, Datei oder Meta) Stufe 2: .git, .env, Backups, phpinfo, Listings und DB-Admin. Nur passive GET/HEAD. KI-Briefing zum Download.",
  ja: "ドメインを入力 — 約1分で評価A–F、進捗表示、nginx/Apache/Traefik/Caddy/Cloudflare/WordPressの修正例。所有確認（DNS・ファイル・meta）後にレベル2：.git / .env / バックアップ / phpinfo / 一覧 / DB管理画面。受動のGET/HEADのみ。AI向け指示もダウンロード可。",
  id: "Masukkan domain — sekitar satu menit nilai A–F, progres langsung, dan perbaikan nginx/Apache/Traefik/Caddy/Cloudflare/WordPress. Setelah bukti kepemilikan (DNS, file, atau meta) buka level 2: .git, .env, backup, phpinfo, listing, dan panel DB. Hanya GET/HEAD pasif. Unduh brief AI.",
  pa: "ਡੋਮੇਨ ਦਰਜ ਕਰੋ — ਲਗਭਗ ਇੱਕ ਮਿੰਟ ਵਿੱਚ ਗ੍ਰੇਡ A–F, ਲਾਈਵ ਤਰੱਕੀ ਅਤੇ nginx/Apache/Traefik/Caddy/Cloudflare/WordPress ਫਿਕਸ। ਮਾਲਕੀ (DNS, ਫਾਈਲ ਜਾਂ meta) ਤੋਂ ਬਾਅਦ ਪੱਧਰ 2: .git, .env, ਬੈਕਅੱਪ, phpinfo, ਲਿਸਟਿੰਗ ਅਤੇ DB ਐਡਮਿਨ। ਸਿਰਫ਼ ਪੈਸਿਵ GET/HEAD। AI ਬ੍ਰੀਫ ਡਾਊਨਲੋਡ ਕਰੋ।",
  jv: "Lebokake domain — watara sedhela nilai A–F, progres langsung, lan perbaikan nginx/Apache/Traefik/Caddy/Cloudflare/WordPress. Sawise bukti kepemilikan (DNS, file, utawa meta) buka level 2: .git, .env, backup, phpinfo, listing, lan panel DB. Mung GET/HEAD pasif. Undhuh brief AI.",
  te: "డొమైన్ ఇవ్వండి — ఒక నిమిషంలో గ్రేడ్ A–F, లైవ్ ప్రోగ్రెస్, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress ఫిక్స్. యాజమాన్యం (DNS, ఫైల్ లేదా meta) తర్వాత స్థాయి 2: .git, .env, బ్యాకప్‌లు, phpinfo, లిస్టింగ్, DB అడ్మిన్. కేవలం పాసివ్ GET/HEAD. AI బ్రీఫ్ డౌన్‌లోడ్ చేయండి.",
  tr: "Alan adı girin — yaklaşık bir dakikada A–F notu, canlı ilerleme ve nginx/Apache/Traefik/Caddy/Cloudflare/WordPress düzeltmeleri. Sahiplik (DNS, dosya veya meta) sonrası seviye 2: .git, .env, yedekler, phpinfo, dizin listeleri ve DB panelleri. Yalnızca pasif GET/HEAD. YZ brief indirin.",
  ko: "도메인을 입력하세요 — 약 1분 만에 A–F 등급, 실시간 진행, nginx/Apache/Traefik/Caddy/Cloudflare/WordPress 수정안. 소유 확인(DNS·파일·meta) 후 레벨 2: .git, .env, 백업, phpinfo, 목록, DB 관리 패널. 수동 GET/HEAD만. AI 브리프 다운로드 가능.",
  mr: "डोमेन टाका — सुमारे एका मिनिटात ग्रेड A–F, लाइव्ह प्रगती आणि nginx/Apache/Traefik/Caddy/Cloudflare/WordPress सुधारणा. मालकी (DNS, फाइल किंवा meta) नंतर स्तर २: .git, .env, बॅकअप, phpinfo, लिस्टिंग आणि DB अॅडमिन. फक्त निष्क्रिय GET/HEAD. AI ब्रीफ डाउनलोड करा.",
  vi: "Nhập tên miền — trong khoảng một phút có điểm A–F, tiến trình trực tiếp và bản sửa nginx/Apache/Traefik/Caddy/Cloudflare/WordPress. Sau xác minh quyền sở hữu (DNS, tệp hoặc meta) mở cấp 2: .git, .env, bản sao lưu, phpinfo, danh sách thư mục và panel DB. Chỉ GET/HEAD thụ động. Tải brief AI.",
  ta: "டொமைனை உள்ளிடுங்கள் — சுமார் ஒரு நிமிடத்தில் A–F தரம், நேரடி முன்னேற்றம், nginx/Apache/Traefik/Caddy/Cloudflare/WordPress திருத்தங்கள். உரிமை (DNS, கோப்பு அல்லது meta) உறுதிக்குப் பின் நிலை 2: .git, .env, காப்பு, phpinfo, பட்டியல், DB நிர்வாகம். செயலற்ற GET/HEAD மட்டும். AI சுருக்கம் பதிவிறக்கவும்.",
  it: "Inserisci un dominio — in circa un minuto voto A–F, avanzamento live e fix per nginx, Apache, Traefik, Caddy, Cloudflare e WordPress. Dopo prova di proprietà (DNS, file o meta) sblocca il livello 2: .git, .env, backup, phpinfo, listing e pannelli DB. Solo GET/HEAD passivi. Scarica un brief per l’IA.",
  fa: "دامنه را وارد کنید — در حدود یک دقیقه نمره A–F، پیشرفت زنده و اصلاحات nginx/Apache/Traefik/Caddy/Cloudflare/WordPress. پس از اثبات مالکیت (DNS، فایل یا meta) سطح ۲ باز می‌شود: .git، .env، بکاپ، phpinfo، فهرست پوشه و پنل دیتابیس. فقط GET/HEAD غیرفعال. خلاصه برای هوش مصنوعی را دانلود کنید.",
  tlh: "Domain yIje'. A–F. nginx Apache Traefik Caddy Cloudflare WordPress. Dom 'oS 'ej 2 yIchu'. .git .env. GET/HEAD neH. AI yIjej. HIvQo'.",
});

const enBody: SeoBody = {
  benefitsTitle: "Why use sitechecker",
  benefits: [
    "Level 1 (no signup): ~29 passive checks — security headers, TLS, cookies, CMS/JS hints, DNS, mail and security.txt.",
    "Level 2 after ownership proof: exposed .git, .env/config backups, SQL/zip dumps, phpinfo, directory listings, phpMyAdmin/Adminer.",
    "Human titles and “why it matters” notes, live progress, A–F grade with top-three fixes, downloadable AI remediation brief.",
    "Copy-paste fixes for nginx, Apache, .htaccess, Traefik, Caddy, Cloudflare and WordPress.",
    "Shareable report link (`/{lang}/?r=…`) — open the ready report in the browser; stays fresh for 24 hours, then the check re-runs in place.",
  ],
  howTitle: "How it works",
  howSteps: [
    "Enter the domain and run level 1, or confirm ownership (DNS TXT, well-known file, or meta tag) and enable level 2.",
    "Workers send only GET/HEAD under SSRF limits; sensitive L2 paths stay owner-gated.",
    "Follow live progress, copy the report link, then open the report: grade, top fixes, evidence and stack-specific patches.",
    "Copy a fix or download the AI brief (with the ready-report URL), deploy, and re-check.",
  ],
  strongTitle: "What we look at",
  strongLead:
    "Level 1 is hygiene any visitor can observe. Level 2 probes sensitive paths only after DNS, file or meta ownership proof. Still not a penetration test — no forms, logins or exploit payloads.",
  tipsLabel: "Tips",
  strongTips: [
    "Enable HSTS only after HTTPS works on every hostname you serve; start CSP in Report-Only.",
    "Prove ownership before deep checks; never leave .git, .env or DB dumps in the web root.",
    "Publish SPF + DKIM and a DMARC policy of quarantine/reject — forged “password reset” mail abuses the same domain users trust on the site.",
    "Opt out anytime with DNS TXT _sitechecker-optout or a note in security.txt.",
  ],
  usesTitle: "Typical uses",
  uses: [
    "Pre-launch checklist for freelancers, studios and small shops.",
    "Quick TLS/header sanity check for ops — plus owner-only deep scan for leaked configs.",
    "Share findings or the AI brief with a client or teammate after fixes.",
  ],
  faqTitle: "FAQ",
  faq: [
    {
      q: "Does this mean my site is secure?",
      a: "No. The report is a passive baseline only. A good grade means fewer obvious hygiene issues — not that the site resists attacks, misconfigurations elsewhere, or compromised accounts.",
    },
    {
      q: "Do you attack my site?",
      a: "No. Workers send only GET and HEAD under SSRF safeguards. No forms, logins, fuzzing, password guessing or exploit payloads — and we never change your site.",
    },
    {
      q: "What is level 1 vs level 2?",
      a: "Level 1 is public hygiene anyone can observe: security headers, TLS, cookies, CMS/JS hints, DNS/mail and security.txt. Level 2 adds probes for .git, .env/config backups, SQL/zip dumps, phpinfo, directory listings and DB admin panels — only after ownership proof.",
    },
    {
      q: "How do I unlock level 2?",
      a: "Open “Confirm domain ownership”, pick DNS TXT, file or meta tag, place the token, then tap “Check token”. Enable the level 2 checkbox and run the scan. Verified status lasts 30 days; the token itself is valid for 7 days until confirmed.",
    },
    {
      q: "Which ownership methods work?",
      a: "DNS TXT on _sitechecker-verify.example.com (covers the domain and subdomains), a file at /.well-known/sitechecker-TOKEN.txt with the token inside, or a sitechecker-verify meta tag on the homepage. One method is enough.",
    },
    {
      q: "Can I scan someone else’s domain?",
      a: "Level 1 only shows what any visitor already sees. Level 2 requires proving you control the domain. Some high-profile domain classes stay blocked from level 2 even with a token.",
    },
    {
      q: "Why check SPF, DKIM and DMARC on a website scanner?",
      a: "Those DNS records protect the domain brand users see on your site. Without them, attackers can forge password-reset, invoice or login-alert mail that looks like yours. Evidence shows the exact TXT name we queried and what we found (or that the record is missing / p=none).",
    },
    {
      q: "How is the A–F grade calculated?",
      a: "The score starts at 100. Failed checks subtract points by severity (critical hits harder than low); warnings subtract half. Info-only items do not change the score. At least one critical finding caps the grade at D. Top three fixes are the highest-impact failures.",
    },
    {
      q: "How long does a check take?",
      a: "Usually under a minute. You see live progress by group (headers, TLS, cookies, files, software, DNS). Level 2 adds a few more path probes and may take a bit longer.",
    },
    {
      q: "How often can I re-check?",
      a: "The same domain can be scanned again after a short cooldown (about 30 seconds). There are also hourly IP limits and a daily per-domain cap so the service stays fair.",
    },
    {
      q: "Which fix formats do you provide?",
      a: "Where it applies: nginx, Apache vhost, .htaccess, Traefik, Caddy, Cloudflare and WordPress, plus a short “other” note. Copy from the finding card or download a Markdown AI remediation brief for the whole report.",
    },
    {
      q: "What is the AI brief?",
      a: "A downloadable Markdown file with the grade, top issues, suggested fixes and a direct link to the ready report — paste it into an assistant. It is a helper, not a guarantee that an automated patch is safe for your stack.",
    },
    {
      q: "Can I share a report link?",
      a: "Yes. When a check starts you get a `/{lang}/?r=<id>` URL you can copy. Opening it shows the ready report while it is fresh (24 hours). After that the same link re-runs the scan and replaces the saved result.",
    },
    {
      q: "Do you store page contents or secrets?",
      a: "No full page bodies or personal data are kept. Reports store metadata and short evidence snippets (up to about 200 characters). Reports expire after 30 days; a shared report stays “fresh” for 24 hours before an automatic re-scan. Audit logs of domain/IP/action are kept longer for abuse handling.",
    },
    {
      q: "The site is behind Cloudflare / a CDN — will results be wrong?",
      a: "We talk to the public hostname like a browser would, so you mostly see edge headers and TLS. Origin-only settings may differ. Prefer Cloudflare / WordPress fix tabs when that is your stack, and re-check after changes propagate.",
    },
    {
      q: "A finding looks like a false positive — what then?",
      a: "Treat evidence as a hint: status codes, headers and short body fragments. CDNs, custom error pages or unusual setups can confuse path probes. Fix what you confirm, ignore what does not match your stack, and re-run after changes.",
    },
    {
      q: "Do I need an account?",
      a: "No. One-off level 1 and ownership-gated level 2 work without registration. History, alerts and paid monitoring are not part of this free baseline.",
    },
    {
      q: "How do I opt out?",
      a: "Publish DNS TXT _sitechecker-optout with value sitechecker-optout (or 1/true), or mention sitechecker-optout in security.txt. Opt-out applies immediately to both levels.",
    },
  ],
  appName: "sitechecker",
};

const ruBody: SeoBody = {
  benefitsTitle: "Зачем sitechecker",
  benefits: [
    "Уровень 1 без регистрации: около 29 пассивных проверок — заголовки, TLS, cookie, CMS/JS, DNS, почта и security.txt.",
    "Уровень 2 после подтверждения владения: открытые .git, бэкапы .env/конфигов, SQL/zip-дампы, phpinfo, листинг каталогов, phpMyAdmin/Adminer.",
    "Человеческие формулировки, живой ход проверки, оценка A–F с top-3 и скачиваемое ТЗ для ИИ.",
    "Копируемые правки для nginx, Apache, .htaccess, Traefik, Caddy, Cloudflare и WordPress.",
    "Ссылка на отчёт (`/{lang}/?r=…`) — открывает готовый результат в браузере; актуальность 24 часа, потом проверка перезапускается на том же id.",
  ],
  howTitle: "Как это работает",
  howSteps: [
    "Введите домен для уровня 1 или подтвердите владение (DNS TXT, файл или meta) и включите уровень 2.",
    "Воркер ходит только GET/HEAD с защитой от SSRF; чувствительные пути L2 — только владельцу.",
    "Смотрите живой прогресс, скопируйте ссылку на отчёт, затем сам отчёт: оценка, главные исправления, доказательства и фиксы под стек.",
    "Скопируйте правку или скачайте ТЗ для ИИ (со ссылкой на готовый отчёт), выкатайте изменения и проверьте снова.",
  ],
  strongTitle: "Что смотрим",
  strongLead:
    "Уровень 1 — гигиена, видимая любому посетителю. Уровень 2 трогает чувствительные пути только после DNS-, файл- или meta-подтверждения владения. Это всё ещё не пентест: без форм, логинов и эксплойтов.",
  tipsLabel: "Подсказки",
  strongTips: [
    "Включайте HSTS, когда HTTPS работает на всех хостах; CSP сначала в Report-Only.",
    "Перед глубокой проверкой подтвердите владение; не держите .git, .env и дампы в web root.",
    "Опубликуйте SPF + DKIM и DMARC с p=quarantine или p=reject — поддельный «сброс пароля» бьёт по тому же домену, которому люди доверяют на сайте.",
    "Отказаться от сканов можно DNS TXT _sitechecker-optout или записью в security.txt.",
  ],
  usesTitle: "Кому полезно",
  uses: [
    "Чеклист перед сдачей сайта клиенту или запуском магазина.",
    "Быстрая сверка TLS и заголовков для админов — плюс глубокий скан своих доменов на утечки.",
    "Передать находки или ТЗ для ИИ коллеге после правок.",
  ],
  faqTitle: "FAQ",
  faq: [
    {
      q: "Это значит, что сайт безопасен?",
      a: "Нет. Отчёт — только пассивная базовая проверка. Хорошая оценка значит меньше явных дыр в гигиене, а не то, что сайт устоит перед атаками, другими ошибками конфигурации или взломанными учётками.",
    },
    {
      q: "Вы атакуете сайт?",
      a: "Нет. Воркер шлёт только GET и HEAD с защитой от SSRF. Без форм, логинов, фаззинга, подбора паролей и эксплойтов — и мы ничего не меняем на вашем сайте.",
    },
    {
      q: "Чем уровень 1 отличается от уровня 2?",
      a: "Уровень 1 — публичная гигиена: заголовки, TLS, cookie, CMS/JS, DNS/почта и security.txt. Уровень 2 добавляет поиск .git, бэкапов .env/конфигов, SQL/zip-дампов, phpinfo, листинга каталогов и админок БД — только после подтверждения владения.",
    },
    {
      q: "Как открыть уровень 2?",
      a: "Откройте «Подтвердить владение доменом», выберите DNS TXT, файл или meta-тег, разместите токен и нажмите «Проверить токен». Включите чекбокс уровня 2 и запустите проверку. Подтверждение действует 30 дней; сам токен живёт 7 дней до успешного confirm.",
    },
    {
      q: "Какие способы подтверждения владения есть?",
      a: "DNS TXT на _sitechecker-verify.example.com (на домен и поддомены), файл /.well-known/sitechecker-TOKEN.txt с токеном внутри или meta-тег sitechecker-verify на главной. Достаточно одного способа.",
    },
    {
      q: "Можно ли проверять чужой домен?",
      a: "Уровень 1 показывает только то, что и так видит любой посетитель. Уровень 2 требует доказательства, что доменом управляете вы. Для части крупных/чувствительных доменов уровень 2 закрыт даже с токеном.",
    },
    {
      q: "Зачем в сканере сайта SPF, DKIM и DMARC?",
      a: "Эти DNS-записи защищают бренд домена, который люди видят на сайте. Без них проще подделать письма о сбросе пароля, счетах или входе «от вас». В доказательстве — точное имя TXT, которое мы смотрели, и что нашли (или что записи нет / стоит p=none).",
    },
    {
      q: "Как считается оценка A–F?",
      a: "Счёт начинается со 100. За fail снимаются баллы по критичности (критичное бьёт сильнее низкого), warn — половина. Info на оценку не влияет. Хотя бы одна критическая находка ограничивает оценку уровнем D. В top-3 — самые весомые fail.",
    },
    {
      q: "Сколько длится проверка?",
      a: "Обычно меньше минуты. Ход видно по группам: заголовки, TLS, cookie, файлы, ПО, DNS. Уровень 2 добавляет несколько запросов к чувствительным путям и может занять чуть дольше.",
    },
    {
      q: "Как часто можно перепроверять?",
      a: "Тот же домен — после короткой паузы (около 30 секунд). Есть лимит с IP в час и суточный лимит на домен, чтобы сервис оставался доступным всем.",
    },
    {
      q: "Какие форматы правок есть?",
      a: "Где уместно: nginx, Apache vhost, .htaccess, Traefik, Caddy, Cloudflare и WordPress, плюс короткая подсказка «другое». Можно копировать из карточки находки или скачать Markdown-ТЗ для ИИ по всему отчёту.",
    },
    {
      q: "Что такое ТЗ для ИИ?",
      a: "Скачиваемый Markdown с оценкой, главными проблемами, предложенными правками и прямой ссылкой на готовый отчёт — его удобно вставить в ассистента. Это помощник, а не гарантия, что автопатч безопасен именно для вашего стека.",
    },
    {
      q: "Можно ли поделиться ссылкой на отчёт?",
      a: "Да. При запуске проверки появляется URL вида `/{lang}/?r=<id>`. По нему открывается готовый отчёт, пока он свежий (24 часа). Позже та же ссылка перезапускает сканирование и заменяет сохранённый результат.",
    },
    {
      q: "Вы храните тела страниц или секреты?",
      a: "Полные тела страниц и персональные данные не сохраняем. В отчёте — метаданные и короткие фрагменты-доказательства (примерно до 200 символов). Отчёты живут 30 дней; «свежесть» шаринга — 24 часа, потом авто-перескан. Журнал IP/домен/действие — дольше, для разбора жалоб.",
    },
    {
      q: "Сайт за Cloudflare / CDN — результаты будут неверными?",
      a: "Мы ходим на публичный хост как браузер, поэтому чаще видим заголовки и TLS на краю. Настройки только на origin могут отличаться. Если стек Cloudflare или WordPress — смотрите соответствующие вкладки фиксов и перепроверяйте после распространения изменений.",
    },
    {
      q: "Похоже на ложное срабатывание — что делать?",
      a: "Смотрите evidence: код ответа, заголовки и короткий фрагмент тела. CDN, кастомные ошибки и нестандартные схемы могут путать проверку путей. Чините то, что подтверждается у себя, остальное отбрасывайте и запускайте скан снова после правок.",
    },
    {
      q: "Нужна ли регистрация?",
      a: "Нет. Разовый уровень 1 и уровень 2 после ownership работают без аккаунта. История, алерты и платный мониторинг в этот бесплатный baseline не входят.",
    },
    {
      q: "Как запретить проверки?",
      a: "DNS TXT _sitechecker-optout со значением sitechecker-optout (или 1/true), либо упоминание sitechecker-optout в security.txt. Запрет действует сразу на оба уровня.",
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
