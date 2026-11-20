package threatdetect;

import javafx.beans.binding.Bindings;
import javafx.beans.binding.StringBinding;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * All the texts of the application in English, French and Arabic.
 * - I18n.t("key", args...) gives the text in the current language.
 * - I18n.bind("key") gives a binding that updates the moment the language changes.
 */
public final class I18n {

    public enum Lang {
        EN("en", false), FR("fr", false), AR("ar", true);

        private final String code;
        private final boolean rtl;

        Lang(String code, boolean rtl) {
            this.code = code;
            this.rtl = rtl;
        }

        public String code() { return code; }
        public boolean rtl() { return rtl; }

        public static Lang fromCode(String code, Lang fallback) {
            for (Lang l : values()) {
                if (l.code.equalsIgnoreCase(code)) return l;
            }
            return fallback;
        }
    }

    private static final ObjectProperty<Lang> LANG = new SimpleObjectProperty<>(Lang.EN);
    private static volatile Lang current = Lang.EN; // readable from worker threads
    private static final Map<Lang, Map<String, String>> TEXTS = new EnumMap<>(Lang.class);

    private I18n() {}

    public static ObjectProperty<Lang> langProperty() { return LANG; }
    public static Lang lang() { return current; }

    public static void setLang(Lang lang) {
        current = lang;
        LANG.set(lang);
    }

    public static String t(String key, Object... args) {
        String pattern = TEXTS.get(current).get(key);
        if (pattern == null) pattern = TEXTS.get(Lang.EN).getOrDefault(key, key);
        return args.length == 0 ? pattern : String.format(Locale.ROOT, pattern, args);
    }

    public static StringBinding bind(String key, Object... args) {
        return Bindings.createStringBinding(() -> t(key, args), LANG);
    }

    public static StringBinding bindFn(Supplier<String> supplier) {
        return Bindings.createStringBinding(supplier::get, LANG);
    }

    private static void add(String key, String en, String fr, String ar) {
        TEXTS.get(Lang.EN).put(key, en);
        TEXTS.get(Lang.FR).put(key, fr);
        TEXTS.get(Lang.AR).put(key, ar);
    }

    static {
        for (Lang l : Lang.values()) TEXTS.put(l, new HashMap<>());

        // ---------- Header ----------
        add("app.title", "Threat Detection", "Détection de menaces", "كشف التهديدات");
        add("app.subtitle",
                "Check links and messages for phishing and scam signals.",
                "Analysez liens et messages pour repérer l'hameçonnage et les arnaques.",
                "افحص الروابط والرسائل بحثًا عن علامات التصيّد والاحتيال.");
        add("theme.dark", "Dark mode", "Mode sombre", "الوضع الداكن");
        add("theme.light", "Light mode", "Mode clair", "الوضع الفاتح");
        add("help.tip", "Keyboard shortcuts", "Raccourcis clavier", "اختصارات لوحة المفاتيح");
        add("help.title", "Keyboard shortcuts", "Raccourcis clavier", "اختصارات لوحة المفاتيح");
        add("help.body",
                "F5  Analyze\nEsc  Cancel\nCtrl+O  Open a CSV file\nCtrl+E  Export results\nCtrl+F  Search\nCtrl+Enter  Add and analyze",
                "F5  Analyser\nÉchap  Annuler\nCtrl+O  Ouvrir un fichier CSV\nCtrl+E  Exporter les résultats\nCtrl+F  Rechercher\nCtrl+Entrée  Ajouter et analyser",
                "F5  تحليل\nEsc  إلغاء\nCtrl+O  فتح ملف CSV\nCtrl+E  تصدير النتائج\nCtrl+F  بحث\nCtrl+Enter  إضافة وتحليل");

        // ---------- Side panel ----------
        add("single.title", "Check one item", "Vérifier un élément", "فحص عنصر واحد");
        add("type.url", "URL", "URL", "رابط");
        add("type.email", "Email", "E-mail", "بريد");
        add("type.sms", "SMS", "SMS", "رسالة");
        add("input.prompt.url", "https://example.com/login", "https://example.com/login", "https://example.com/login");
        add("input.prompt.msg",
                "Paste the email or SMS text here",
                "Collez ici le texte de l'e-mail ou du SMS",
                "الصق نص البريد أو الرسالة هنا");
        add("err.empty.url", "Enter a URL to check.", "Saisissez une URL à vérifier.", "أدخل رابطًا لفحصه.");
        add("err.empty.msg", "Paste a message to check.", "Collez un message à vérifier.", "الصق رسالة لفحصها.");
        add("err.toolong",
                "That's %d characters. The limit is %d.",
                "Ce texte compte %d caractères. La limite est de %d.",
                "النص يتكون من %d حرفًا، والحد الأقصى %d.");
        add("btn.add", "Add to list", "Ajouter à la liste", "إضافة إلى القائمة");
        add("btn.addrun", "Add and analyze", "Ajouter et analyser", "إضافة وتحليل");
        add("batch.title", "Check a batch", "Vérifier un lot", "فحص مجموعة");
        add("batch.hint",
                "Choose a CSV file with one item per row. Columns: type, content. Type is url, email or sms. Leave it out and the app guesses.",
                "Choisissez un fichier CSV avec un élément par ligne. Colonnes : type, contenu. Le type est url, email ou sms. S'il manque, l'application le devine.",
                "اختر ملف CSV يحتوي على عنصر واحد في كل سطر. الأعمدة: النوع، المحتوى. النوع هو url أو email أو sms. وإذا لم يُذكر فسيخمّنه التطبيق.");
        add("btn.csv", "Choose CSV file…", "Choisir un fichier CSV…", "اختيار ملف CSV…");
        add("tip.csv", "Ctrl+O", "Ctrl+O", "Ctrl+O");
        add("csv.none", "No file chosen", "Aucun fichier choisi", "لم يُختر أي ملف");
        add("csv.loaded", "%s: %d items", "%s : %d éléments", "%s: %d عنصر");
        add("btn.demo", "Load demo data", "Charger des données de démonstration", "تحميل بيانات تجريبية");
        add("demo.hint",
                "Adds sample items, including ones that can't be verified.",
                "Ajoute des exemples, dont certains impossibles à vérifier.",
                "يضيف عناصر تجريبية، من بينها عناصر لا يمكن التحقق منها.");
        add("settings.title", "Performance", "Performance", "الأداء");
        add("settings.workers", "Parallel checks", "Vérifications en parallèle", "الفحوصات المتوازية");
        add("settings.workers.hint",
                "How many items are analyzed at the same time.",
                "Nombre d'éléments analysés simultanément.",
                "عدد العناصر التي تُحلَّل في الوقت نفسه.");

        // ---------- Risk levels and statuses ----------
        add("risk.high", "High", "Élevé", "مرتفع");
        add("risk.medium", "Medium", "Moyen", "متوسط");
        add("risk.low", "Low", "Faible", "منخفض");
        add("risk.unverified", "Not Verified", "Non vérifié", "غير متحقق منه");
        add("st.queued", "Queued", "En attente", "في الانتظار");
        add("st.analyzing", "Analyzing", "En cours", "قيد التحليل");
        add("st.completed", "Completed", "Terminé", "مكتمل");
        add("st.unverified", "Not Verified", "Non vérifié", "غير متحقق منه");
        add("st.cancelled", "Cancelled", "Annulé", "مُلغى");

        // ---------- Results panel ----------
        add("btn.analyze", "Analyze", "Analyser", "تحليل");
        add("btn.cancel", "Cancel", "Annuler", "إلغاء");
        add("btn.retry", "Retry Not Verified", "Relancer les non vérifiés", "إعادة فحص غير المتحقق منها");
        add("btn.remove", "Remove selected", "Supprimer la sélection", "حذف المحدد");
        add("btn.clear", "Clear all", "Tout effacer", "مسح الكل");
        add("btn.export", "Export CSV", "Exporter en CSV", "تصدير CSV");
        add("tip.analyze",
                "Check everything not yet analyzed (F5).",
                "Analyser tout ce qui ne l'est pas encore (F5).",
                "تحليل كل ما لم يُحلَّل بعد (F5).");
        add("tip.cancel",
                "Stop the running checks (Esc).",
                "Arrêter les vérifications en cours (Échap).",
                "إيقاف الفحوصات الجارية (Esc).");
        add("tip.retry",
                "Run again only the items that couldn't be verified.",
                "Relancer uniquement les éléments non vérifiés.",
                "إعادة تشغيل العناصر التي تعذّر التحقق منها فقط.");
        add("tip.export",
                "Save the rows shown in the table (Ctrl+E).",
                "Enregistrer les lignes affichées (Ctrl+E).",
                "حفظ الصفوف المعروضة في الجدول (Ctrl+E).");
        add("search.prompt",
                "Search inputs and details…  (Ctrl+F)",
                "Rechercher dans les entrées et les détails…  (Ctrl+F)",
                "ابحث في المُدخلات والتفاصيل…  (Ctrl+F)");
        add("filter.all", "All", "Tous", "الكل");
        add("count.items", "%d items", "%d éléments", "%d عنصر");
        add("count.one", "1 item", "1 élément", "عنصر واحد");
        add("count.showing", "Showing %d of %d", "%d affichés sur %d", "عرض %d من %d");

        add("col.id", "#", "#", "#");
        add("col.input", "INPUT", "ENTRÉE", "المُدخل");
        add("col.type", "TYPE", "TYPE", "النوع");
        add("col.risk", "RISK", "RISQUE", "الخطورة");
        add("col.status", "STATUS", "STATUT", "الحالة");
        add("col.progress", "PROGRESS", "PROGRESSION", "التقدم");
        add("col.time", "TIME", "DURÉE", "المدة");
        add("col.details", "DETAILS", "DÉTAILS", "التفاصيل");

        add("empty.title", "Nothing to show", "Rien à afficher", "لا شيء لعرضه");
        add("empty.text",
                "Add a URL or a message, or choose a CSV file.",
                "Ajoutez une URL ou un message, ou choisissez un fichier CSV.",
                "أضف رابطًا أو رسالة، أو اختر ملف CSV.");

        add("details.title", "Selected item", "Élément sélectionné", "العنصر المحدد");
        add("details.hint",
                "Select a row to see its full details.",
                "Sélectionnez une ligne pour voir ses détails.",
                "اختر صفًا لعرض تفاصيله الكاملة.");
        add("details.multi", "%d rows selected.", "%d lignes sélectionnées.", "تم تحديد %d صفوف.");
        add("details.why", "WHY THIS RESULT", "POURQUOI CE RÉSULTAT", "سبب هذه النتيجة");
        add("details.time", "Analyzed in %s", "Analysé en %s", "تم التحليل في %s");
        add("btn.copy", "Copy input", "Copier l'entrée", "نسخ المُدخل");
        add("menu.reanalyze", "Re-analyze", "Ré-analyser", "إعادة التحليل");
        add("menu.copy", "Copy input", "Copier l'entrée", "نسخ المُدخل");
        add("menu.remove", "Remove", "Supprimer", "حذف");

        // ---------- Status bar ----------
        add("run.count", "%d running", "%d en cours", "%d قيد التشغيل");
        add("counter.done", "%d of %d done", "%d sur %d terminés", "اكتمل %d من %d");
        add("msg.ready", "Ready", "Prêt", "جاهز");
        add("msg.added", "Added item %d.", "Élément %d ajouté.", "تمت إضافة العنصر %d.");
        add("msg.demo",
                "Added %d demo items. Press Analyze.",
                "%d éléments de démonstration ajoutés. Cliquez sur Analyser.",
                "تمت إضافة %d عنصرًا تجريبيًا. اضغط على تحليل.");
        add("msg.nofile", "No file chosen.", "Aucun fichier choisi.", "لم يُختر أي ملف.");
        add("msg.reading", "Reading %s…", "Lecture de %s…", "جارٍ قراءة %s…");
        add("msg.readfail", "Couldn't read the file.", "Impossible de lire le fichier.", "تعذّرت قراءة الملف.");
        add("msg.nothingimport", "Nothing to import from %s.", "Rien à importer depuis %s.", "لا شيء لاستيراده من %s.");
        add("msg.imported.skipped",
                "Imported %d items from %s. Skipped %d.",
                "%d éléments importés depuis %s. %d ignorés.",
                "تم استيراد %d عنصرًا من %s وتخطّي %d.");
        add("msg.imported",
                "Imported %d items from %s. Press Analyze.",
                "%d éléments importés depuis %s. Cliquez sur Analyser.",
                "تم استيراد %d عنصرًا من %s. اضغط على تحليل.");
        add("msg.noexport", "Nothing to export.", "Rien à exporter.", "لا شيء لتصديره.");
        add("msg.exportcancel", "Export cancelled.", "Exportation annulée.", "أُلغي التصدير.");
        add("msg.exporting", "Exporting…", "Exportation…", "جارٍ التصدير…");
        add("msg.exported", "Exported %d rows to %s.", "%d lignes exportées vers %s.", "تم تصدير %d صفًا إلى %s.");
        add("msg.exportfail", "Export failed.", "Échec de l'exportation.", "فشل التصدير.");
        add("msg.addfirst",
                "Add something to check first.",
                "Ajoutez d'abord quelque chose à vérifier.",
                "أضف شيئًا لفحصه أولًا.");
        add("msg.alldone",
                "Everything in the list has already been analyzed.",
                "Tout a déjà été analysé.",
                "تم تحليل كل ما في القائمة بالفعل.");
        add("msg.noretry",
                "There are no Not Verified items to retry.",
                "Aucun élément non vérifié à relancer.",
                "لا توجد عناصر غير متحقق منها لإعادة فحصها.");
        add("msg.analyzing",
                "Analyzing… %d of %d done",
                "Analyse… %d sur %d terminés",
                "جارٍ التحليل… اكتمل %d من %d");
        add("msg.cancelled", "Analysis cancelled.", "Analyse annulée.", "أُلغي التحليل.");
        add("msg.done", "Done. %d processed in %s.", "Terminé. %d traités en %s.", "اكتمل. تمت معالجة %d خلال %s.");
        add("msg.done.unv",
                "Done. %d processed, %d not verified, in %s.",
                "Terminé. %d traités, %d non vérifiés, en %s.",
                "اكتمل. تمت معالجة %d، منها %d غير متحقق منها، خلال %s.");
        add("msg.removed.one", "Removed 1 item.", "1 élément supprimé.", "تم حذف عنصر واحد.");
        add("msg.removed", "Removed %d items.", "%d éléments supprimés.", "تم حذف %d عناصر.");
        add("msg.cleared", "List cleared.", "Liste vidée.", "تم مسح القائمة.");
        add("msg.copied",
                "Input copied to the clipboard.",
                "Entrée copiée dans le presse-papiers.",
                "تم نسخ المُدخل إلى الحافظة.");

        // ---------- Toasts ----------
        add("toast.done", "Analysis finished.", "Analyse terminée.", "اكتمل التحليل.");
        add("toast.done.high",
                "Analysis finished: %d high-risk item(s).",
                "Analyse terminée : %d élément(s) à risque élevé.",
                "اكتمل التحليل: %d عنصر عالي الخطورة.");
        add("toast.exported", "Results exported.", "Résultats exportés.", "تم تصدير النتائج.");
        add("toast.imported", "%d items imported.", "%d éléments importés.", "تم استيراد %d عنصرًا.");
        add("toast.copied", "Copied.", "Copié.", "تم النسخ.");

        // ---------- Dialogs ----------
        add("dialog.csv", "Choose a CSV file", "Choisir un fichier CSV", "اختيار ملف CSV");
        add("dialog.export", "Export results", "Exporter les résultats", "تصدير النتائج");
        add("filter.csv", "CSV files (*.csv)", "Fichiers CSV (*.csv)", "ملفات CSV (*.csv)");
        add("filter.files", "All files", "Tous les fichiers", "كل الملفات");
        add("alert.err.read", "Couldn't read the file", "Impossible de lire le fichier", "تعذّرت قراءة الملف");
        add("alert.noRows", "No usable rows in %s", "Aucune ligne exploitable dans %s", "لا توجد صفوف صالحة في %s");
        add("alert.empty", "The file is empty.", "Le fichier est vide.", "الملف فارغ.");
        add("alert.allbad",
                "Every row had a problem. See the details below.",
                "Chaque ligne pose problème. Voir les détails ci-dessous.",
                "كل الصفوف بها مشكلة. راجع التفاصيل أدناه.");
        add("alert.partial.header",
                "Imported %d items, skipped %d rows",
                "%d éléments importés, %d lignes ignorées",
                "تم استيراد %d عنصرًا وتخطّي %d صفًا");
        add("alert.partial.body",
                "The skipped rows are listed below. Fix them in the file and import again if you need them.",
                "Les lignes ignorées sont listées ci-dessous. Corrigez-les dans le fichier puis réimportez-le si besoin.",
                "الصفوف المتخطاة مدرجة أدناه. صحّحها في الملف وأعد الاستيراد إن لزم الأمر.");
        add("alert.save.err", "Couldn't save the file", "Impossible d'enregistrer le fichier", "تعذّر حفظ الملف");
        add("alert.save.locked",
                "The file couldn't be written. If it is open in Excel, close it and try again.",
                "Impossible d'écrire le fichier. S'il est ouvert dans Excel, fermez-le puis réessayez.",
                "تعذّرت كتابة الملف. إذا كان مفتوحًا في Excel فأغلقه وحاول مرة أخرى.");

        // ---------- CSV loader ----------
        add("csv.err.notfound",
                "The file could not be found. It may have been moved or deleted.",
                "Fichier introuvable. Il a peut-être été déplacé ou supprimé.",
                "تعذّر العثور على الملف. ربما نُقل أو حُذف.");
        add("csv.err.folder",
                "That is a folder, not a CSV file.",
                "Il s'agit d'un dossier, pas d'un fichier CSV.",
                "هذا مجلد وليس ملف CSV.");
        add("csv.err.notcsv",
                "That doesn't look like a CSV file. Choose a file ending in .csv.",
                "Ce n'est pas un fichier CSV. Choisissez un fichier se terminant par .csv.",
                "لا يبدو أن هذا ملف CSV. اختر ملفًا بامتداد csv.");
        add("csv.err.unreadable",
                "The file can't be read. Check its permissions.",
                "Le fichier est illisible. Vérifiez ses autorisations.",
                "لا يمكن قراءة الملف. تحقق من الأذونات.");
        add("csv.err.utf8",
                "The file isn't UTF-8 text. Save it again as CSV (UTF-8).",
                "Le fichier n'est pas en UTF-8. Enregistrez-le à nouveau en CSV (UTF-8).",
                "الملف ليس بترميز UTF-8. احفظه من جديد بصيغة CSV (UTF-8).");
        add("csv.err.quote", "Line %d: a quote is never closed.", "Ligne %d : un guillemet n'est pas fermé.", "السطر %d: علامة اقتباس غير مغلقة.");
        add("csv.err.empty", "Line %d: the content is empty.", "Ligne %d : le contenu est vide.", "السطر %d: المحتوى فارغ.");
        add("csv.err.long", "Line %d: longer than %d characters.", "Ligne %d : plus de %d caractères.", "السطر %d: أطول من %d حرفًا.");

        // ---------- Export header ----------
        add("exp.id", "id", "id", "المعرّف");
        add("exp.type", "type", "type", "النوع");
        add("exp.input", "input", "entrée", "المُدخل");
        add("exp.risk", "risk", "risque", "الخطورة");
        add("exp.status", "status", "statut", "الحالة");
        add("exp.seconds", "seconds", "secondes", "الثواني");
        add("exp.details", "details", "détails", "التفاصيل");

        // ---------- Row texts ----------
        add("item.waiting", "Waiting to be analyzed.", "En attente d'analyse.", "بانتظار التحليل.");
        add("item.start", "Waiting to start.", "En attente de démarrage.", "بانتظار البدء.");
        add("item.checking", "Checking…", "Vérification…", "جارٍ الفحص…");
        add("item.cancelled",
                "Cancelled before a result was available.",
                "Annulé avant l'obtention d'un résultat.",
                "أُلغي قبل ظهور نتيجة.");
        add("item.incomplete",
                "The check could not be completed.",
                "La vérification n'a pas pu aboutir.",
                "تعذّر إكمال الفحص.");
        add("item.error", "Unexpected error: %s", "Erreur inattendue : %s", "خطأ غير متوقع: %s");

        // ---------- Mock backend ----------
        add("mock.empty", "Empty input.", "Entrée vide.", "المُدخل فارغ.");
        add("mock.url.spaces",
                "Malformed URL: it contains spaces or line breaks.",
                "URL mal formée : elle contient des espaces ou des retours à la ligne.",
                "رابط غير صالح: يحتوي على مسافات أو فواصل أسطر.");
        add("mock.url.syntax", "Malformed URL: %s.", "URL mal formée : %s.", "رابط غير صالح: %s.");
        add("mock.url.scheme",
                "Unsupported scheme \"%s\". Only http and https can be checked.",
                "Schéma « %s » non pris en charge. Seuls http et https peuvent être vérifiés.",
                "البروتوكول «%s» غير مدعوم. يمكن فحص http وhttps فقط.");
        add("mock.url.nohost",
                "Malformed URL: no host name found.",
                "URL mal formée : aucun nom d'hôte trouvé.",
                "رابط غير صالح: لم يُعثر على اسم المضيف.");
        add("mock.timeout",
                "Network timeout after 5 s (mock).",
                "Délai réseau dépassé après 5 s (simulation).",
                "انتهت مهلة الشبكة بعد 5 ثوانٍ (محاكاة).");
        add("mock.ratelimit",
                "Rate limit reached (HTTP 429). Try again later (mock).",
                "Limite de requêtes atteinte (HTTP 429). Réessayez plus tard (simulation).",
                "بلغ الحدّ المسموح من الطلبات (HTTP 429). حاول لاحقًا (محاكاة).");
        add("mock.unavailable",
                "Security service unavailable (mock).",
                "Service de sécurité indisponible (simulation).",
                "خدمة الأمان غير متاحة (محاكاة).");
        add("mock.score", "Score %d: %s.", "Score %d : %s.", "النتيجة %d: %s.");
        add("mock.safe",
                "No suspicious patterns found (mock rules).",
                "Aucun motif suspect détecté (règles simulées).",
                "لم يتم رصد أي أنماط مشبوهة (قواعد محاكاة).");
        add("sep", ", ", ", ", "، ");
        add("r.http", "uses HTTP, not HTTPS", "utilise HTTP et non HTTPS", "يستخدم HTTP بدل HTTPS");
        add("r.ip", "IP address as host name", "adresse IP comme nom d'hôte", "عنوان IP بدل اسم نطاق");
        add("r.at", "contains an @ that hides the real host", "contient un @ qui masque le vrai hôte", "يحتوي على @ يُخفي المضيف الحقيقي");
        add("r.subdomains", "many subdomains", "nombreux sous-domaines", "نطاقات فرعية كثيرة");
        add("r.keyword", "sensitive keyword in the address", "mot-clé sensible dans l'adresse", "كلمة حساسة في العنوان");
        add("r.long", "very long address", "adresse très longue", "عنوان طويل جدًا");
        add("r.urgent", "urgent language", "langage d'urgence", "لغة استعجال");
        add("r.cred", "asks for credentials or codes", "demande des identifiants ou des codes", "يطلب بيانات دخول أو رموزًا");
        add("r.prize", "prize or reward claim", "promesse de gain ou de récompense", "ادّعاء جائزة أو مكافأة");
        add("r.link", "contains a link", "contient un lien", "يحتوي على رابط");
    }
}

