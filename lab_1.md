# דוח מעבדה: מ-CTI לתחקור SOC ומיפוי MITRE ATT&CK

**נושא המעבדה:** חקירת דוח מודיעין איומים (CTI) ומיפוי להתקפת CVE-2025-13659 (Ivanti Endpoint Manager RCE)
**חברי הקבוצה:** רוני רייכר

## 1. בחירת דוח ה-CTI וסיכום התקיפה

* **כותרת הדוח:** CVE-2025-13659: Ivanti Endpoint Manager RCE Vulnerability

* **מפרסם:** SentinelOne (Vulnerability Database)

* **תאריך פרסום:** 22 באפריל 2026

* **קישור ישיר:** [CVE-2025-13659 - SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-13659/)

**סיכום התקיפה:**
פגיעות CVE-2025-13659 היא חולשת ביצוע קוד מרחוק (RCE) וכתיבת קבצים שרירותיים במוצר Ivanti Endpoint Manager (EPM). הפגיעות מאפשרת לתוקף מרוחק, שאינו מאומת אך דורש אינטראקציה מסוימת מצד המשתמש, לנצל ליקוי בבקרת הקוד והטיפול בקלט כדי לכתוב קבצים זדוניים (כגון Web Shell) בסביבת השרת. מכיוון ששרתי EPM פועלים בסביבות ארגוניות ברשאות מערכת גבוהות לצורך ניהול קצוות רשת (Endpoints), פריצה לשרת זה מעניקה לתוקפים נקודת שליטה מרכזית וקריטית על כלל תשתיות הארגון. תרחיש התקיפה כולל שליחת בקשות HTTP מעוותות לנצל את מנגנוני הטיפול בקבצים של היישום, כתיבת קוד זדוני לנתיב נגיש בשרת, והרצתו לצורך השגת השפעה מלאה (Remote Code Execution) והשתלטות על תשתיות הניהול הארגוניות.

## 2. חילוץ התנהגויות ותיאור זרימת התקיפה (Attack Flow)

ההתנהגויות המרכזיות שזוהו בדוח:

1. **שליחת בקשות HTTP זדוניות / ניצול נקודת הקצה (Initial Access / Exploitation):** תוקף שאינו מאומת שולח בקשות רשת המנצלות פגיעות בניהול קוד דינמי/כתיבת קבצים.

2. **כתיבת קבצים שרירותיים (Arbitrary File Write / Web Shell Staging):** יצירת קובץ סקריפט או Web Shell בנתיב הנגיש לשרת ה-Web של היישום.

3. **הפעלת קוד מרחוק / הרצת תהליכים מתוך תהליך השרת (Execution):** הרצת הקוד הזדוני שהועלה כדי לבצע פעולות פוסט-אקספלויטציה.

4. **תנועה רוחבית / שליטה בציוד קצה (Impact / Lateral Movement):** ניצול שרת ה-EPM המרכזי כדי לפגוע בתחנות קצה מנוהלות ברשת הארגונית.

**דיאגרמת זרימה (Attack Sequence):**
`Unauthenticated Remote Attacker` $\rightarrow$ `HTTP Exploit Request to EPM` $\rightarrow$ `Arbitrary File Write (Web Shell Drop)` $\rightarrow$ `Web Server Process Spawning Execution` $\rightarrow$ `Full EPM Infrastructure / Endpoint Compromise`

## 3. מיפוי להתנהגויות MITRE ATT&CK

| התנהגות נצפית (Observed Behavior) | טקטיקת ATT&CK (Tactic) | טכניקה / מזהה (Technique / ID) | ראיות ונימוק למיפוי (Evidence & Rationale) | 
| ----- | ----- | ----- | ----- | 
| **שליחת בקשות רשת מנצלות פגיעות (Exploit Public-Facing Application)** | Initial Access | Exploit Public-Facing Application (T1190) | הדוח מציין כי תוקף מרוחק שאינו מאומת מנצל חולשה ב-Ivanti EPM כדי לכתוב קבצים ולהריץ קוד. | 
| **כתיבת קבצים זדוניים / Web Shell בשרת** | Persistence / Server Software Component | Create or Modify System Process / Web Shell (T1505.003) | הדוח מתאר כתיבת קבצים שרירותיים (כגון Web Shell) במיקומים נגישים בשרת לצורך ביסוס שליטה. | 
| **תהליך השרת מריץ פקודות או סקריפטים (Process Spawning)** | Execution | Command and Scripting Interpreter (T1059) | ניצול הפגיעות מוביל להרצת קוד מרחוק כאשר תהליך השרת מריץ פקודות או קבצי סקריפט. | 

## 4. חיבור לתחקור SOC (Telemetry & Investigation)

1. **עבור טכניקת Exploit Public-Facing Application (T1190):**

   * **מקור טלמטריה:** לוגי גישה של שרת ה-Web / WAF / לוגי HTTP Request.

   * **תפקיד אנליסט Tier 1:** בדיקת התראות מערכת הגנה או זיהוי בקשות HTTP חשודות (כגון POST חריג או פרמטרים הכוללים תווים מוזרים/נתיבים ארוכים) אל מול נקודות קצה רגישות ב-EPM.

   * **תפקיד אנליסט Tier 2:** ניתוח עומק של תעבורת הרשת, בדיקת ה-Payload שהועבר בבקשה, ואימות האם התקיפה הצליחה לגרום לשינוי במערכת או להורדת קבצים.

2. **עבור טכניקת Web Shell / כתיבת קבצים שרירותיים (T1505.003):**

   * **מקור טלמטריה:** אירועי יצירת קבצים במערכת ההפעלה (File Creation Events) בתיקיות ה-Web root או בתיקיות זמניות (Temp), וכן לוגים של EDR.

   * **תפקיד אנליסט Tier 1:** התראת EDR על יצירת קובץ סקריפט חדש (למשל .asp, .aspx, .php) בתוך תיקיות של יישום ה-Web.

   * **תפקיד אנליסט Tier 2:** בדיקת תוכן הקובץ שנוצר, בדיקת חתימות דיגיטליות או מחרוזות חשודות (Web Shell signatures), ואימות זמני יצירה מול מועד קבלת בקשות הרשת החשודות.

3. **עבור טכניקת Command and Scripting Interpreter / Process Spawning:**

   * **מקור טלמטריה:** לוגי יצירת תהליכים (Process Creation - Sysmon Event ID 1 / Windows Security Event ID 4688).

   * **תפקיד אנליסט Tier 1:** זיהוי תהליך שרת (כגון תהליך עזר של ה-EPM) שמוליד תהליך בן חשוד כמו `cmd.exe`, `powershell.exe` או סקריפטים חיצוניים.

   * **תפקיד אנליסט Tier 2:** מעקב אחר שורת הפקודה המלאה (Command Line) של התהליך שנוצר, בדיקת פעילויות המשך (האם בוצעה הרצת פקודות איסוף מידע או התחברות החוצה ל-C2).

## 5. דיון, סקירה ומיפוי לא ודאי (Uncertain Mapping)

* **מיפוי שנוי במחלוקת / לא ודאי:** השאלה האם שלב כתיבת הקובץ השרירותי (Arbitrary File Write) הוביל מיד להרצת קוד או שימש תחילה לאיסוף מידע פסיבי והנחת תשתיות (Staging) בלבד טרם הפעלה ידנית על ידי התוקף.

* **עדויות נוספות הנדרשות לאימות או הפרכה:** בדיקת זיכרון (Memory Forensics) של תהליכי השרת בזמן אמת, ניתוח קבצי ה-Dump של היישום, ובחינת פלט לוגים של תקשורת יוצאת (Outbound Network Connections) מהשרת אל כתובות חיצוניות לא מוכרות.

* **תיקון המיפוי במידת הצורך:** במידה ומתברר שהקובץ נכתב אך לא הופעל באופן מידי, יש להוסיף את טקטיקת *Persistence* (התבססות) לצד *Execution*.