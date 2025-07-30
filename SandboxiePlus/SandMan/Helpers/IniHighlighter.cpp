#include "stdafx.h"
#include "IniHighlighter.h"
#include "../MiscHelpers/Common/Settings.h"
#include "../version.h"


// Settings validation and tooltip handling
const QString CIniHighlighter::DEFAULT_SETTINGS_FILE = "SbieSettings.ini";
const QString CIniHighlighter::DEFAULT_VERSION = "0.0.0";

QVersionNumber CIniHighlighter::s_currentVersion;
QString CIniHighlighter::s_currentLanguage;
QMutex CIniHighlighter::s_languageMutex;

QHash<QString, SettingInfo> CIniHighlighter::validSettings;
QDateTime CIniHighlighter::lastFileModified;
bool CIniHighlighter::settingsLoaded = false;
QMutex CIniHighlighter::settingsMutex;

QHash<QString, QString> CIniHighlighter::tooltipCache;
QMutex CIniHighlighter::tooltipCacheMutex;

CIniHighlighter::KeywordMappings<CIniHighlighter::KeywordType::Context> CIniHighlighter::contextKeywordMappings;
CIniHighlighter::LocalizedKeywordMappings<CIniHighlighter::KeywordType::Context> CIniHighlighter::localizedContextKeywordMappings;
CIniHighlighter::KeywordMappings<CIniHighlighter::KeywordType::Category> CIniHighlighter::categoryKeywordMappings;
CIniHighlighter::LocalizedKeywordMappings<CIniHighlighter::KeywordType::Category> CIniHighlighter::localizedCategoryKeywordMappings;
CIniHighlighter::KeywordMappings<CIniHighlighter::KeywordType::Requirements> CIniHighlighter::requirementsKeywordMappings;
CIniHighlighter::LocalizedKeywordMappings<CIniHighlighter::KeywordType::Requirements> CIniHighlighter::localizedRequirementsKeywordMappings;
CIniHighlighter::TooltipStyle CIniHighlighter::contextTooltipStyle;
CIniHighlighter::TooltipStyle CIniHighlighter::categoryTooltipStyle;
CIniHighlighter::TooltipStyle CIniHighlighter::requirementsTooltipStyle;
// Settings validation and tooltip handling

QVersionNumber CIniHighlighter::getCurrentVersion()
{
	if (s_currentVersion.isNull()) {
		QMutexLocker locker(&settingsMutex);
		if (s_currentVersion.isNull()) {
			QString versionStr = QString("%1.%2.%3").arg(VERSION_MJR).arg(VERSION_MIN).arg(VERSION_REV);
			s_currentVersion = QVersionNumber::fromString(versionStr);
		}
	}
	return s_currentVersion;
}

QString CIniHighlighter::getCurrentLanguage()
{
	if (s_currentLanguage.isNull()) {
		QMutexLocker locker(&s_languageMutex);
		if (s_currentLanguage.isNull()) {
			// Get the current UI language from configuration
			QString language = theConf->GetString("Options/UiLanguage");

			// Handle special case "native" (use default values)
			if (language.compare("native", Qt::CaseInsensitive) == 0) {
				s_currentLanguage = "";
				return s_currentLanguage;
			}

			// If no language is set, determine from system locale
			if (language.isEmpty()) {
				language = QLocale::system().name();
			}

			// For English variants, return empty to use default values
			if (language.startsWith("en", Qt::CaseInsensitive)) {
				s_currentLanguage = "";
			}
			else {
				s_currentLanguage = language.toLower();
			}
		}
	}
	return s_currentLanguage;
}

CIniHighlighter::CIniHighlighter(bool bDarkMode, QTextDocument* parent, bool enableValidation)
	: QSyntaxHighlighter(parent), m_enableValidation(enableValidation)
{
    // Define colors for light and dark mode
    QColor blue = bDarkMode ? QColor("#87CEFA") : QColor("#0000FF"); // Lighter blue for dark mode
    QColor green = bDarkMode ? QColor("#90EE90") : QColor("#008000"); // Lighter green for dark mode
    QColor darkRed = bDarkMode ? QColor("#FF6347") : QColor("#800000"); // Lighter red for dark mode
    QColor red = bDarkMode ? QColor("#FF4500") : QColor("#FF0000"); // Brighter red for dark mode
    QColor black = bDarkMode ? QColor("#DCDCDC") : QColor("#000000"); // Light gray for dark mode
    QColor brown = bDarkMode ? QColor("#F4A460") : QColor("#A52A2A"); // Light brown for dark mode
    QColor purple = bDarkMode ? QColor("#DA70D6") : QColor("#800080"); // Brighter purple for dark mode
    QColor gray = bDarkMode ? QColor("#A9A9A9") : QColor("#808080"); // Lighter gray for dark mode

    HighlightRule rule;

    // Section headers: [Section]
    sectionFormat.setForeground(blue);
    sectionFormat.setFontWeight(QFont::Bold);
    rule.pattern = QRegularExpression("^\\s*\\[.*\\]\\s*$");
    rule.format = sectionFormat;
    highlightRules.append(rule);

    // Comments: ; comment or # comment
    commentFormat.setForeground(green);
    rule.pattern = QRegularExpression("^\\s*[;#].*");
    rule.format = commentFormat;
    highlightRules.append(rule);

    // Keys: key=
    keyFormat.setForeground(darkRed);
    rule.pattern = QRegularExpression("^[\\w\\.]+(?=\\s*=)");
    rule.format = keyFormat;
    highlightRules.append(rule);

    // Equals sign: =
    equalsFormat.setForeground(red);
    rule.pattern = QRegularExpression("=");
    rule.format = equalsFormat;
    highlightRules.append(rule);

    // Values: =value
    valueFormat.setForeground(black);
    rule.pattern = QRegularExpression("(?<=\\=).*");
    rule.format = valueFormat;
    highlightRules.append(rule);

    // Initialize formats for value prefix and first comma
    valuePrefixFormat.setForeground(blue);
    firstCommaFormat.setForeground(red);
	
	// Future key format
	futureKeyFormat.setForeground(QColor("darkCyan"));
	futureKeyFormat.setBackground(QColor("white"));

	// Removed key format
	removedKeyFormat.setForeground(QColor("white"));
	removedKeyFormat.setBackground(QColor("black"));
	removedKeyFormat.setFontStrikeOut(true);

	// Renamed key format
	renamedKeyFormat.setForeground(QColor("black"));
	renamedKeyFormat.setBackground(QColor("yellow"));
	renamedKeyFormat.setFontItalic(true);
	
	// Unknown key format
	unknownKeyFormat.setUnderlineStyle(QTextCharFormat::SpellCheckUnderline);
	unknownKeyFormat.setUnderlineColor(red);

#ifdef INI_WITH_JSON
    // Initialize JSON formats
    jsonKeyFormat.setForeground(brown);
    jsonStringFormat.setForeground(black);
    jsonNumberFormat.setForeground(blue);
    jsonBoolNullFormat.setForeground(purple);
    jsonBracesFormat.setForeground(gray);
    jsonColonFormat.setForeground(red);
    jsonCommaFormat.setForeground(red);

    // 1. JSON Colon: Match colons not preceded by backslash
    HighlightRule jsonRule;
    jsonRule.pattern = QRegularExpression(R"((?<!\\):)");
    jsonRule.format = jsonColonFormat;
    jsonHighlightRules.append(jsonRule);

    // 2. JSON Comma: Match commas not preceded by backslash
    jsonRule.pattern = QRegularExpression(R"((?<!\\),)");
    jsonRule.format = jsonCommaFormat;
    jsonHighlightRules.append(jsonRule);

    // 3. JSON Keys: "key":
    jsonRule.pattern = QRegularExpression(R"("(?:(?:\\.)|[^"\\])*"(?=\s*:))");
    jsonRule.format = jsonKeyFormat;
    jsonHighlightRules.append(jsonRule);

    // 4. JSON Strings: "value" (excluding keys)
    jsonRule.pattern = QRegularExpression(R"("(?:(?:\\.)|[^"\\])*"(?!\s*:))");
    jsonRule.format = jsonStringFormat;
    jsonHighlightRules.append(jsonRule);

    // 5. JSON Numbers: 123, 45.67
    jsonRule.pattern = QRegularExpression(R"(\b-?\d+(\.\d+)?\b)");
    jsonRule.format = jsonNumberFormat;
    jsonHighlightRules.append(jsonRule);

    // 6. JSON Booleans and Null: true, false, null
    jsonRule.pattern = QRegularExpression(R"(\b(true|false|null)\b)", QRegularExpression::CaseInsensitiveOption);
    jsonRule.format = jsonBoolNullFormat;
    jsonHighlightRules.append(jsonRule);

    // 7. JSON Braces and Brackets: { }, [ ]
    jsonRule.pattern = QRegularExpression(R"([\{\}\[\]])");
    jsonRule.format = jsonBracesFormat;
    jsonHighlightRules.append(jsonRule);
#endif

	// Check if we need to load the settings file - with mutex protection
	QString settingsPath = QCoreApplication::applicationDirPath() + "/" + DEFAULT_SETTINGS_FILE;
	QFileInfo fileInfo(settingsPath);

	bool needToLoad = false;
	{
		QMutexLocker locker(&settingsMutex); // Lock for checking cache status
		needToLoad = !settingsLoaded || !fileInfo.exists() || fileInfo.lastModified() > lastFileModified;
	}

	if (needToLoad) {
		loadSettingsIni(settingsPath);
	}
	else {
		qDebug() << "[validSettings] Using cached settings (" << validSettings.size() << " entries)";
	}

	// Use cached version instead of creating a new one each time
	m_currentVersion = getCurrentVersion();
}

CIniHighlighter::~CIniHighlighter()
{
}

void CIniHighlighter::setCurrentVersion(const QString& version)
{
	m_currentVersion = QVersionNumber::fromString(version);
}

// Load settings from SbieSettings.ini
void CIniHighlighter::loadSettingsIni(const QString& filePath)
{
	QMutexLocker locker(&settingsMutex); // Lock during the entire load operation

	// Clear tooltip cache when settings are reloaded
	{
		QMutexLocker cacheLock(&tooltipCacheMutex);
		tooltipCache.clear();
	}

	// Clear language cache with its own mutex
	{
		QMutexLocker languageLock(&s_languageMutex);
		s_currentLanguage = QString();
	}

	QFile file(filePath);
	if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
		validSettings.clear();
		contextKeywordMappings.clear();
		localizedContextKeywordMappings.clear();
		categoryKeywordMappings.clear();
		localizedCategoryKeywordMappings.clear();
		requirementsKeywordMappings.clear();
		localizedRequirementsKeywordMappings.clear();
		contextTooltipStyle = TooltipStyle();
		categoryTooltipStyle = TooltipStyle();
		requirementsTooltipStyle = TooltipStyle();

		QTextStream in(&file);
#if QT_VERSION < QT_VERSION_CHECK(6,0,0)
		// Qt5: use setCodec
		in.setCodec("UTF-8");
#endif

		QString currentSection;
		SettingInfo currentInfo;
		bool inSection = false;
		bool inConfigSection = false;

		while (!in.atEnd()) {
			QString line = in.readLine().trimmed();

			// Skip empty lines and comments
			if (line.isEmpty() || line.startsWith(';') || line.startsWith('#'))
				continue;

			// Check if this is a section header [SectionName]
			QRegularExpression sectionRegex(R"(^\[([^\]]+)\]\s*$)");
			QRegularExpressionMatch sectionMatch = sectionRegex.match(line);

			if (sectionMatch.hasMatch()) {
				// If we were already processing a section, save it (except for config section)
				if (inSection && !currentSection.isEmpty() && !inConfigSection) {
					currentInfo.name = currentSection;
					validSettings.insert(currentInfo.name, currentInfo);
				}

				// Start a new section
				currentSection = sectionMatch.captured(1).trimmed();
				inConfigSection = (currentSection == "___SbieSettingsConfig_");

				if (!inConfigSection) {
					currentInfo = SettingInfo(); // Reset info for new regular section
					inSection = true;
				}
				else {
					// We're entering the special config section
					inSection = false;
				}
				continue;
			}

			// If not in a section yet, skip
			if (!inSection && !inConfigSection)
				continue;

			// Process key=value pairs
			int equalsPos = line.indexOf('=');
			if (equalsPos > 0) {
				QString key = line.left(equalsPos).trimmed();
				QString value = line.mid(equalsPos + 1).trimmed();

				if (inConfigSection) {
					// Process configuration settings
					if (key.compare("_ContextConf", Qt::CaseInsensitive) == 0) {
						// Parse default context keyword mappings
						contextKeywordMappings = parseKeywordMappings<KeywordType::Context>(value);
					}
					else if (key.startsWith("_ContextConf_", Qt::CaseInsensitive)) {
						// Handle localized context mappings
						QRegularExpression langRegex("^_ContextConf_(.+)$", QRegularExpression::CaseInsensitiveOption);
						QRegularExpressionMatch langMatch = langRegex.match(key);

						if (langMatch.hasMatch()) {
							QString langCode = langMatch.captured(1).toLower();
							localizedContextKeywordMappings.insert(langCode, parseKeywordMappings<KeywordType::Context>(value));
						}
					}
					else if (key.compare("_CategoryConf", Qt::CaseInsensitive) == 0) {
						// Parse default category keyword mappings
						categoryKeywordMappings = parseKeywordMappings<KeywordType::Category>(value);
					}
					else if (key.startsWith("_CategoryConf_", Qt::CaseInsensitive)) {
						// Handle localized category mappings
						QRegularExpression langRegex("^_CategoryConf_(.+)$", QRegularExpression::CaseInsensitiveOption);
						QRegularExpressionMatch langMatch = langRegex.match(key);

						if (langMatch.hasMatch()) {
							QString langCode = langMatch.captured(1).toLower();
							localizedCategoryKeywordMappings.insert(langCode, parseKeywordMappings<KeywordType::Category>(value));
						}
					}
					else if (key.compare("_RequirementsConf", Qt::CaseInsensitive) == 0) {
						// Parse default requirements keyword mappings
						requirementsKeywordMappings = parseKeywordMappings<KeywordType::Requirements>(value);
					}
					else if (key.startsWith("_RequirementsConf_", Qt::CaseInsensitive)) {
						// Handle localized requirements mappings
						QRegularExpression langRegex("^_RequirementsConf_(.+)$", QRegularExpression::CaseInsensitiveOption);
						QRegularExpressionMatch langMatch = langRegex.match(key);

						if (langMatch.hasMatch()) {
							QString langCode = langMatch.captured(1).toLower();
							localizedRequirementsKeywordMappings.insert(langCode, parseKeywordMappings<KeywordType::Requirements>(value));
						}
					}
					else if (key.compare("_ContextStyles", Qt::CaseInsensitive) == 0) {
						// Parse context tooltip style configuration
						contextTooltipStyle = parseStyleConfig(value);
					}
					else if (key.compare("_CategoryStyles", Qt::CaseInsensitive) == 0) {
						// Parse category tooltip style configuration
						categoryTooltipStyle = parseStyleConfig(value);
					}
					else if (key.compare("_RequirementsStyles", Qt::CaseInsensitive) == 0) {
						// Parse requirements tooltip style configuration
						requirementsTooltipStyle = parseStyleConfig(value);
					}
				}
				else {
					// Process normal setting fields
					// Helper function to sanitize version strings
					auto sanitizeVersion = [this](const QString& s, bool defaultZero = false) {
						QString v = s.trimmed();
						v.remove(QRegularExpression("[^0-9.]"));
						QRegularExpression rx("^[0-9]+\\.[0-9]+\\.[0-9]+$"); // Exact x.y.z format
						if (rx.match(v).hasMatch())
							return v;
						return defaultZero ? QString(DEFAULT_VERSION) : QString();
						};

					// Process special fields
					if (key.compare("AddedVersion", Qt::CaseInsensitive) == 0)
						currentInfo.addedVersion = sanitizeVersion(value, true);
					else if (key.compare("RemovedVersion", Qt::CaseInsensitive) == 0)
						currentInfo.removedVersion = sanitizeVersion(value);
					else if (key.compare("ReaddedVersion", Qt::CaseInsensitive) == 0)
						currentInfo.readdedVersion = sanitizeVersion(value);
					else if (key.compare("RenamedVersion", Qt::CaseInsensitive) == 0)
						currentInfo.renamedVersion = sanitizeVersion(value);
					else if (key.compare("SupersededBy", Qt::CaseInsensitive) == 0)
						currentInfo.supersededBy = value;
					else if (key.compare("Category", Qt::CaseInsensitive) == 0)
						currentInfo.category = value;
					else if (key.compare("Context", Qt::CaseInsensitive) == 0)
						currentInfo.context = value;
					// Handle localized syntax (Syntax_XX=value)
					else if (key.startsWith("Syntax_", Qt::CaseInsensitive)) {
						// Modified regex to capture any language code after Syntax_
						QRegularExpression langRegex("^Syntax_(.+)$", QRegularExpression::CaseInsensitiveOption);
						QRegularExpressionMatch langMatch = langRegex.match(key);

						if (langMatch.hasMatch()) {
							// Get the language code and normalize to lowercase for consistent matching
							QString langCode = langMatch.captured(1).toLower();
							QString localizedStx = value;

							// Replace \n escape sequences with actual newlines
							localizedStx.replace("\\n", "\n");

							// If there's already content for this language, append with newline
							if (currentInfo.localizedSyntax.contains(langCode)) {
								currentInfo.localizedSyntax[langCode] += "\n" + localizedStx;
							}
							else {
								currentInfo.localizedSyntax.insert(langCode, localizedStx);
							}
						}
					}
					else if (key.compare("Syntax", Qt::CaseInsensitive) == 0)
						currentInfo.syntax = value;
					// Handle localized descriptions (Description_XX=value)
					else if (key.startsWith("Description_", Qt::CaseInsensitive)) {
						// Modified regex to capture any language code after Description_
						QRegularExpression langRegex("^Description_(.+)$", QRegularExpression::CaseInsensitiveOption);
						QRegularExpressionMatch langMatch = langRegex.match(key);

						if (langMatch.hasMatch()) {
							// Get the language code and normalize to lowercase for consistent matching
							QString langCode = langMatch.captured(1).toLower();
							QString localizedDesc = value;

							// Replace \n escape sequences with actual newlines
							localizedDesc.replace("\\n", "\n");

							// If there's already content for this language, append with newline
							if (currentInfo.localizedDescriptions.contains(langCode)) {
								currentInfo.localizedDescriptions[langCode] += "\n" + localizedDesc;
							}
							else {
								currentInfo.localizedDescriptions.insert(langCode, localizedDesc);
							}
						}
					}
					else if (key.compare("Description", Qt::CaseInsensitive) == 0)
						currentInfo.description = value;
					else if (key.compare("Requirements", Qt::CaseInsensitive) == 0)
						currentInfo.requirements = value.toLower().trimmed();
				}
			}
		}

		// Don't forget to save the last section (if not the config section)
		if (inSection && !currentSection.isEmpty() && !inConfigSection) {
            currentInfo.name = currentSection;
            // Ensure name contains only valid characters
            currentInfo.name.remove(QRegularExpression("[^a-zA-Z0-9_.]"));
            validSettings.insert(currentInfo.name, currentInfo);
        }

		file.close();

		// Update the cache status after successful load
		lastFileModified = QFileInfo(filePath).lastModified();
		settingsLoaded = true;

		qDebug() << "[validSettings] Successfully loaded" << validSettings.size() << "settings,"
			<< contextKeywordMappings.size() << "context mappings,"
			<< localizedContextKeywordMappings.size() << "localized context mappings,"
			<< categoryKeywordMappings.size() << "category mappings,"
			<< localizedCategoryKeywordMappings.size() << "localized category mappings,"
			<< requirementsKeywordMappings.size() << "requirements mappings, and"
			<< localizedRequirementsKeywordMappings.size() << "localized requirements mappings from" << filePath;
	}
	else {
		// File couldn't be opened - log the error
		qWarning() << "[validSettings] Failed to load settings file:" << filePath << "Error:" << file.errorString();

		// Keep settings loaded flag false so we try again next time
		settingsLoaded = false;
	}
}

template<CIniHighlighter::KeywordType Type>
CIniHighlighter::KeywordMappings<Type> CIniHighlighter::parseKeywordMappings(const QString& value)
{
	KeywordMappings<Type> mappings;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
	QStringList mappingStrings = value.split(';', Qt::SkipEmptyParts);
#else
	QStringList mappingStrings = value.split(';', QString::SkipEmptyParts);
#endif

	for (const QString& mapping : mappingStrings) {
		QStringList parts = mapping.split('|');
		if (parts.size() >= 2) {
			KeywordInfo<Type> info;
			info.keyword = parts[0].trimmed();
			info.displayName = parts[1].trimmed();
			if (parts.size() >= 3) {
				info.action = parts[2].trimmed();
			}
			mappings.append(info);
		}
	}

	return mappings;
}

template CIniHighlighter::KeywordMappings<CIniHighlighter::KeywordType::Context>
CIniHighlighter::parseKeywordMappings<CIniHighlighter::KeywordType::Context>(const QString& value);

template CIniHighlighter::KeywordMappings<CIniHighlighter::KeywordType::Category>
CIniHighlighter::parseKeywordMappings<CIniHighlighter::KeywordType::Category>(const QString& value);

template CIniHighlighter::KeywordMappings<CIniHighlighter::KeywordType::Requirements>
CIniHighlighter::parseKeywordMappings<CIniHighlighter::KeywordType::Requirements>(const QString& value);

CIniHighlighter::TooltipStyle CIniHighlighter::parseStyleConfig(const QString& styleConfig)
{
	TooltipStyle style;

	if (styleConfig.isEmpty()) {
		return style; // Return default (empty) style
	}

	QStringList parts = styleConfig.split('|');

	// Parse color (first part)
	if (parts.size() >= 1 && !parts[0].trimmed().isEmpty()) {
		style.color = parts[0].trimmed().toLower();
	}

	// Parse format requirements (second part)
	if (parts.size() >= 2 && !parts[1].trimmed().isEmpty()) {
		QString formatStr = parts[1].trimmed().toLower();
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
		QStringList formats = formatStr.split(',', Qt::SkipEmptyParts);
#else
		QStringList formats = formatStr.split(',', QString::SkipEmptyParts);
#endif

		for (const QString& format : formats) {
			QString fmt = format.trimmed();
			if (fmt == "bold") {
				style.bold = true;
			}
			else if (fmt == "italic") {
				style.italic = true;
			}
			else if (fmt == "underline") {
				style.underline = true;
			}
		}
	}

	// Parse font (third part) - currently not used in TooltipStyle but could be extended
	if (parts.size() >= 3 && !parts[2].trimmed().isEmpty()) {
		// Font parsing could be added here if needed in the future
		// style.fontFamily = parts[2].trimmed();
	}

	return style;
}

QString CIniHighlighter::GetSettingTooltip(const QString& settingName)
{
	// Early safety check - if settings aren't loaded yet, don't try to access them
	if (!settingsLoaded || settingName.isEmpty())
		return QString();

	// Check tooltip cache first (fast path)
	{
		QMutexLocker cacheLock(&tooltipCacheMutex);
		QHash<QString, QString>::const_iterator it = tooltipCache.find(settingName);
		if (it != tooltipCache.end())
			return it.value();
	}

	// HTML escaping helper function
	auto escapeHtml = [](const QString& str) -> QString {
		QString escaped = str;
		escaped.replace("&", "&amp;");  // Must be first to avoid double-escaping
		escaped.replace("<", "&lt;");
		escaped.replace(">", "&gt;");
		escaped.replace("\"", "&quot;");
		escaped.replace("'", "&#39;");
		return escaped;
		};

	// Generate tooltip content (requires settings lock)
	QString tooltip;
	{
		QMutexLocker locker(&settingsMutex); // Thread-safe access to shared data

		// Double-check after acquiring the lock
		if (!settingsLoaded || validSettings.isEmpty() || !validSettings.contains(settingName))
			return QString();

		// Get the current UI language from configuration
		QString currentLang = getCurrentLanguage();

		const SettingInfo& info = validSettings[settingName];

		// Define the table style once
		const QString tableStyle = "style='border:none; white-space:nowrap;'";

		// Define the cell style once to avoid repetition
		const QString labelStyle = "style='text-align:left; padding-right:8px;'";
		const QString valuePrefix = ": ";

		// Create a table structure for aligned label-value pairs
		tooltip = "<table " + tableStyle + ">";

		// Add setting name row with merged cells - make the name bold and centered
		tooltip += "<tr><td colspan='2' style='text-align:left; font-weight:bold;'>" + settingName + "</td></tr>";

		// Add all available fields as rows with aligned labels and values
		if (!info.addedVersion.isEmpty() && info.addedVersion != DEFAULT_VERSION) {
			tooltip += "<tr><td " + labelStyle + ">" + tr("Added in version") + "</td>";
			tooltip += "<td>" + valuePrefix + info.addedVersion + "</td></tr>";
		}

		if (!info.removedVersion.isEmpty()) {
			tooltip += "<tr><td " + labelStyle + ">" + tr("Removed in version") + "</td>";
			tooltip += "<td>" + valuePrefix + info.removedVersion + "</td></tr>";
		}

		if (!info.readdedVersion.isEmpty()) {
			tooltip += "<tr><td " + labelStyle + ">" + tr("Re-added in version") + "</td>";
			tooltip += "<td>" + valuePrefix + info.readdedVersion + "</td></tr>";
		}

		if (!info.renamedVersion.isEmpty()) {
			tooltip += "<tr><td " + labelStyle + ">" + tr("Renamed in version") + "</td>";
			tooltip += "<td>" + valuePrefix + info.renamedVersion + "</td></tr>";
		}

		if (!info.supersededBy.isEmpty()) {
			tooltip += "<tr><td " + labelStyle + ">" + tr("Superseded by") + "</td>";
			tooltip += "<td>" + valuePrefix + info.supersededBy + "</td></tr>";
		}

		if (!info.category.isEmpty()) {
			QString categoryDisplay = info.category;

			// Get the appropriate category mappings based on language
			KeywordMappings<KeywordType::Category> effectiveMappings;

			// First try exact match for language-specific mappings
			if (localizedCategoryKeywordMappings.contains(currentLang)) {
				effectiveMappings = localizedCategoryKeywordMappings.value(currentLang);
			}
			// Try with just the language part (if it's a locale with country code like "en_US")
			else if (currentLang.contains('_') &&
				localizedCategoryKeywordMappings.contains(currentLang.left(currentLang.indexOf('_')))) {
				effectiveMappings = localizedCategoryKeywordMappings.value(
					currentLang.left(currentLang.indexOf('_')));
			}
			// Fall back to default if no localized mappings found
			else {
				effectiveMappings = categoryKeywordMappings;
			}

			// Process category mappings
			processKeywordMappings<KeywordInfo<KeywordType::Category>>(
				categoryDisplay,
				effectiveMappings,
				tr("Category"),
				labelStyle,
				valuePrefix,
				categoryTooltipStyle,
				tooltip);
		}

		if (!info.context.isEmpty()) {
			QString contextDisplay = info.context;

			// Get the appropriate context mappings
			KeywordMappings<KeywordType::Context> effectiveMappings;

			// First try exact match for language-specific mappings
			if (localizedContextKeywordMappings.contains(currentLang)) {
				effectiveMappings = localizedContextKeywordMappings.value(currentLang);
			}
			// Try with just the language part
			else if (currentLang.contains('_') &&
				localizedContextKeywordMappings.contains(currentLang.left(currentLang.indexOf('_')))) {
				effectiveMappings = localizedContextKeywordMappings.value(
					currentLang.left(currentLang.indexOf('_')));
			}
			// Fall back to default
			else {
				effectiveMappings = contextKeywordMappings;
			}

			// Process context mappings
			processKeywordMappings<KeywordInfo<KeywordType::Context>>(
				contextDisplay,
				effectiveMappings,
				tr("Context"),
				labelStyle,
				valuePrefix,
				contextTooltipStyle,
				tooltip);
		}

		// Choose syntax based on language
		QString syntax = info.syntax; // Default first;
		if (!currentLang.isEmpty()) {
			// First try exact match
			if (info.localizedSyntax.contains(currentLang)) {
				syntax = info.localizedSyntax[currentLang];
			}
			// Try with just the language part (if it's a locale with country code)
			else if (currentLang.contains('_')) {
				QString langBase = currentLang.left(currentLang.indexOf('_'));
				if (info.localizedSyntax.contains(langBase))
					syntax = info.localizedSyntax[langBase];
			}
		}

		if (!syntax.isEmpty()) {
			// Handle the syntax to preserve its own line breaks
			QStringList syntaxLines = syntax.split('\n');
			tooltip += "<tr><td " + labelStyle + " style='vertical-align:top;'>" + tr("Syntax") + "</td>";

			// Process the first line - highlight square brackets in blue (not bold)
			if (!syntaxLines.isEmpty()) {
				QString processedLine = syntaxLines[0];

				// First replace [sn] placeholder with the actual setting name
				processedLine.replace("[sn]", settingName);

				// Then escape HTML special characters
				processedLine = escapeHtml(processedLine);

				// Finally apply styling to square brackets
				processedLine.replace("[", "<span style='color:#2196F3;'>[</span>");
				processedLine.replace("]", "<span style='color:#2196F3;'>]</span>");

				tooltip += "<td>" + valuePrefix + "<span style='font-family: Consolas, monospace;'>" + processedLine + "</span>";

				// Add additional syntax lines with proper indentation
				for (int i = 1; i < syntaxLines.size(); i++) {
					processedLine = syntaxLines[i];

					// Replace [sn] placeholder with the actual setting name
					processedLine.replace("[sn]", settingName);

					// Escape HTML special characters
					processedLine = escapeHtml(processedLine);

					// Apply styling to square brackets
					processedLine.replace("[", "<span style='color:#2196F3;'>[</span>");
					processedLine.replace("]", "<span style='color:#2196F3;'>]</span>");

					tooltip += "<br>&nbsp;&nbsp;<span style='font-family: Consolas, monospace;'>" + processedLine + "</span>";
				}
				tooltip += "</td></tr>";
			}
		}

		// Choose description based on language
		QString description = info.description; // Default first

		if (!currentLang.isEmpty()) {
			// First try exact match
			if (info.localizedDescriptions.contains(currentLang)) {
				description = info.localizedDescriptions[currentLang];
			}
			// Try with just the language part (if it's a locale with country code)
			else if (currentLang.contains('_')) {
				QString langBase = currentLang.left(currentLang.indexOf('_'));
				if (info.localizedDescriptions.contains(langBase))
					description = info.localizedDescriptions[langBase];
			}
		}

		if (!description.isEmpty()) {
			// Handle the description to preserve its own line breaks
			QStringList descLines = description.split('\n');
			tooltip += "<tr><td " + labelStyle + " style='vertical-align:top;'>" + tr("Description") + "</td>";

			// Escape HTML in the first line
			tooltip += "<td>" + valuePrefix + escapeHtml(descLines[0]);

			// Add additional description lines with proper indentation
			for (int i = 1; i < descLines.size(); i++) {
				// Escape HTML in each description line
				tooltip += "<br>&nbsp;&nbsp;" + escapeHtml(descLines[i]);
			}
			tooltip += "</td></tr>";
		}

		if (!info.requirements.isEmpty()) {
			QString requirementsDisplay = info.requirements;

			// Get the appropriate requirements mappings based on language
			KeywordMappings<KeywordType::Requirements> effectiveMappings;

			// First try exact match for language-specific mappings
			if (localizedRequirementsKeywordMappings.contains(currentLang)) {
				effectiveMappings = localizedRequirementsKeywordMappings.value(currentLang);
			}
			// Try with just the language part (if it's a locale with country code like "en_US")
			else if (currentLang.contains('_') &&
				localizedRequirementsKeywordMappings.contains(currentLang.left(currentLang.indexOf('_')))) {
				effectiveMappings = localizedRequirementsKeywordMappings.value(
					currentLang.left(currentLang.indexOf('_')));
			}
			// Fall back to default if no localized mappings found
			else {
				effectiveMappings = requirementsKeywordMappings;
			}

			// Process requirements mappings
			processKeywordMappings<KeywordInfo<KeywordType::Requirements>>(
				requirementsDisplay,
				effectiveMappings,
				tr("Requirements"),
				labelStyle,
				valuePrefix,
				requirementsTooltipStyle,
				tooltip);
		}

		tooltip += "</table>";
	}

	// Store the generated tooltip in cache
	if (!tooltip.isEmpty()) {
		QMutexLocker cacheLock(&tooltipCacheMutex);
		tooltipCache.insert(settingName, tooltip);
	}

	return tooltip;
}

bool CIniHighlighter::IsCommentLine(const QString& line)
{
	// Skip lines that start with # or ; (after optional whitespace)
	QString trimmed = line.trimmed();
	return trimmed.startsWith('#') || trimmed.startsWith(';');
}

void CIniHighlighter::highlightBlock(const QString &text)
{
    // First, reset all formatting
    setFormat(0, text.length(), QTextCharFormat());

    // 1. Check if the entire line is a comment
    QRegularExpression commentRegex(R"(^\s*[;#].*)");
    QRegularExpressionMatch commentMatch = commentRegex.match(text);
    if (commentMatch.hasMatch()) {
        setFormat(0, text.length(), commentFormat);
        return; // Skip other rules
    }

    // 2. Apply INI highlighting rules (section, key, equals, value)
    for (const HighlightRule &rule : qAsConst(highlightRules)) {
        // Skip the comment rule as it's already handled
        if (rule.format.foreground() == commentFormat.foreground())
            continue;

        QRegularExpressionMatchIterator matchIterator = rule.pattern.globalMatch(text);
        while (matchIterator.hasNext()) {
            QRegularExpressionMatch match = matchIterator.next();
            int start = match.capturedStart();
            int length = match.capturedLength();
            setFormat(start, length, rule.format);
        }
    }

	// 3. Highlight keys based on validSettings and currentVersion
	if (m_enableValidation) {
		QRegularExpression keyRegex("^([^\\s=]+)\\s*=");
		QRegularExpressionMatch keyMatch = keyRegex.match(text);
		if (keyMatch.hasMatch()) {
			QString keyName = keyMatch.captured(1);
			int start = keyMatch.capturedStart(1);
			int length = keyName.length();

			if (!validSettings.isEmpty()) { // Only check if list is loaded
				if (validSettings.contains(keyName)) {
					const SettingInfo& info = validSettings[keyName];
					QVersionNumber current = m_currentVersion;
					QVersionNumber renamed = QVersionNumber::fromString(info.renamedVersion);
					QVersionNumber readded = QVersionNumber::fromString(info.readdedVersion);
					QVersionNumber removed = QVersionNumber::fromString(info.removedVersion);
					QVersionNumber added = QVersionNumber::fromString(info.addedVersion);

					if (!info.renamedVersion.isEmpty() && current >= renamed) {
						setFormat(start, length, renamedKeyFormat);
					}
					else if (!info.readdedVersion.isEmpty() && current >= readded) {
						setFormat(start, length, keyFormat);
					}
					else if (!info.removedVersion.isEmpty() && current >= removed) {
						setFormat(start, length, removedKeyFormat);
					}
					else if (current >= added) {
						setFormat(start, length, keyFormat);
					}
					else if (current < added) {
						setFormat(start, length, futureKeyFormat);
					}
					else {
						setFormat(start, length, unknownKeyFormat);
					}
				}
				else {
					setFormat(start, length, unknownKeyFormat); // underline unknown keys
				}
			}
		}
	}

	// 4. Process the value part for value prefixes and first comma
    // Find the position of '=' to identify the start of the value
    int equalsIndex = text.indexOf('=');
    if (equalsIndex != -1) {
        // Start position of the value (after '=')
        int valueStart = equalsIndex + 1;
        QString valueText = text.mid(valueStart).trimmed();

        // Iterate through the value to find the first comma outside of {}
        int braceLevel = 0;
        int firstRelevantCommaIndex = -1;
        for (int i = 0; i < valueText.length(); ++i) {
            QChar currentChar = valueText[i];
            if (currentChar == '{') {
                braceLevel++;
            } else if (currentChar == '}') {
                if (braceLevel > 0)
                    braceLevel--;
            } else if (currentChar == ',' && braceLevel == 0) {
                firstRelevantCommaIndex = i;
                break;
            }
        }

        if (firstRelevantCommaIndex != -1) {
            // Position of the first comma relative to the entire line
            int commaPos = valueStart + firstRelevantCommaIndex;

            // Highlight text before the first comma in blue
            if (firstRelevantCommaIndex > 0) {
                setFormat(valueStart, firstRelevantCommaIndex, valuePrefixFormat);
            }

            // Highlight the first comma in red
            setFormat(commaPos, 1, firstCommaFormat);
        }

#ifdef INI_WITH_JSON
        bool inString = false;
        int stringStart = -1;

        for (int i = firstRelevantCommaIndex != -1 ? firstRelevantCommaIndex + 1 : 0; i < valueText.length(); ++i) {
            QChar currentChar = valueText[i];

            if (currentChar == '\"') {
                // Check if the quote is escaped
                bool escaped = false;
                int backslashCount = 0;
                int j = i - 1;
                while (j >= 0 && valueText[j] == '\\') {
                    backslashCount++;
                    j--;
                }
                if (backslashCount % 2 == 1)
                    escaped = true;

                if (!escaped) {
                    if (!inString) {
                        inString = true;
                        stringStart = valueStart + i;
                    }
                    else {
                        inString = false;
                        // Apply string formatting from stringStart to current position
                        int length = (valueStart + i + 1) - stringStart;
                        setFormat(stringStart, length, jsonStringFormat);
                    }
                }
            }

            // Apply colon and comma formatting only if not inside a string
            if (!inString) {
                if (currentChar == ':') {
                    setFormat(valueStart + i, 1, jsonColonFormat);
                }
                else if (currentChar == ',') {
                    setFormat(valueStart + i, 1, jsonCommaFormat);
                }
            }
        }

        // If still inside a string (unclosed), format till end
        if (inString && stringStart != -1) {
            int length = text.length() - stringStart;
            setFormat(stringStart, length, jsonStringFormat);
        }

        // 4. Apply JSON Key Formatting within JSON Substrings
        // Find all JSON substrings and apply key formatting
        int current = 0;
        while (current < valueText.length()) {
            int startBrace = valueText.indexOf('{', current);
            if (startBrace == -1)
                break;
            int braceCounter = 1;
            int endBrace = startBrace + 1;
            while (endBrace < valueText.length() && braceCounter > 0) {
                if (valueText[endBrace] == '{')
                    braceCounter++;
                else if (valueText[endBrace] == '}')
                    braceCounter--;
                endBrace++;
            }
            if (braceCounter == 0) {
                // Found a JSON substring from startBrace to endBrace-1
                QString jsonString = valueText.mid(startBrace, endBrace - startBrace);
                QRegularExpression keyRegex(R"("(?:(?:\\.)|[^"\\])*"(?=\s*:))");
                QRegularExpressionMatchIterator keyMatches = keyRegex.globalMatch(jsonString);
                while (keyMatches.hasNext()) {
                    QRegularExpressionMatch keyMatch = keyMatches.next();
                    int keyStart = valueStart + startBrace + keyMatch.capturedStart();
                    int keyLength = keyMatch.capturedLength();
                    setFormat(keyStart, keyLength, jsonKeyFormat);
                }
                current = endBrace;
            }
            else {
                break;
            }
        }
#endif
    }
}