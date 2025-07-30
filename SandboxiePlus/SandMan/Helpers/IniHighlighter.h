#pragma once

#include <QSyntaxHighlighter>
#include <QVersionNumber>

#define INI_WITH_JSON

struct HighlightRule {
	QRegularExpression pattern;
	QTextCharFormat format;
};

// Settings validation and tooltip handling
struct SettingInfo {
	QString name;
	QString addedVersion;
	QString removedVersion;
	QString readdedVersion;
	QString renamedVersion;
	QString supersededBy;
	QString category;
	QString context;
	QString syntax;
	QMap<QString, QString> localizedSyntax;
	QString description;
	QMap<QString, QString> localizedDescriptions;
	QString requirements;
};
// Settings validation and tooltip handling

class CIniHighlighter : public QSyntaxHighlighter
{
    Q_OBJECT

public:
	explicit CIniHighlighter(bool bDarkMode, QTextDocument* parent = nullptr, bool enableValidation = true);
	virtual ~CIniHighlighter();

	// Settings validation and tooltip handling
	void loadSettingsIni(const QString& filePath);

	void setCurrentVersion(const QString& version);

	static QString GetSettingTooltip(const QString& settingName);

	static bool IsSettingsLoaded() { return settingsLoaded; }

	static bool IsCommentLine(const QString& line);

	static QHash<QString, QString> tooltipCache;
	static QMutex tooltipCacheMutex;

	static QString s_currentLanguage;
	static QMutex s_languageMutex;
	static QString getCurrentLanguage();
	// Settings validation and tooltip handling

protected:
    void highlightBlock(const QString &text) override;

private:
    QVector<HighlightRule> highlightRules;

    QTextCharFormat sectionFormat;
    QTextCharFormat keyFormat;
    QTextCharFormat valueFormat;
    QTextCharFormat commentFormat;
    QTextCharFormat equalsFormat; // New format for '=' character
    QTextCharFormat valuePrefixFormat; // Format for text before first comma in value
    QTextCharFormat firstCommaFormat;  // Format for the first comma in value
	QTextCharFormat futureKeyFormat;   // Format for future keys
	QTextCharFormat removedKeyFormat;  // Format for removed keys
	QTextCharFormat renamedKeyFormat;  // Format for renamed keys
	QTextCharFormat unknownKeyFormat;  // Format for unknown keys

#ifdef INI_WITH_JSON
    // JSON-specific formats
    QTextCharFormat jsonKeyFormat;
    QTextCharFormat jsonStringFormat;
    QTextCharFormat jsonNumberFormat;
    QTextCharFormat jsonBoolNullFormat;
    QTextCharFormat jsonBracesFormat;
    QTextCharFormat jsonColonFormat;
    QTextCharFormat jsonCommaFormat;

    // JSON highlighting rules
    QVector<HighlightRule> jsonHighlightRules;
#endif

	// Settings validation and tooltip handling
	QVersionNumber m_currentVersion;

	bool m_enableValidation;

	static const QString DEFAULT_SETTINGS_FILE;
	static const QString DEFAULT_VERSION;

	static QVersionNumber s_currentVersion;
	static QVersionNumber getCurrentVersion();

	static QHash<QString, SettingInfo> validSettings;
	static QDateTime lastFileModified;
	static bool settingsLoaded;
	static QMutex settingsMutex;

	// Define keyword types
	enum class KeywordType {
		Context,
		Category,
		Requirements
	};

	// Common keyword info structure for keys
	template<KeywordType Type>
	struct KeywordInfo {
		QString keyword;
		QString displayName;
		QString action;
	};

	struct TooltipStyle {
		QString color = "";           // red, green, blue, etc.
		bool bold = false;
		bool italic = false;
		bool underline = false;

		QString toHtmlStyle() const {
			QStringList styles;
			if (!color.isEmpty()) {
				styles << QString("color:%1").arg(color);
			}
			if (bold) {
				styles << "font-weight:bold";
			}
			if (italic) {
				styles << "font-style:italic";
			}
			if (underline) {
				styles << "text-decoration:underline";
			}
			return styles.isEmpty() ? "" : QString("style='%1'").arg(styles.join(";"));
		}
	};

	// Define type aliases for mappings
	template<KeywordType Type>
	using KeywordMappings = QList<KeywordInfo<Type>>;
	template<KeywordType Type>
	using LocalizedKeywordMappings = QMap<QString, KeywordMappings<Type>>;

	// Static members with specific type instantiations
	static KeywordMappings<KeywordType::Context> contextKeywordMappings;
	static LocalizedKeywordMappings<KeywordType::Context> localizedContextKeywordMappings;
	static KeywordMappings<KeywordType::Category> categoryKeywordMappings;
	static LocalizedKeywordMappings<KeywordType::Category> localizedCategoryKeywordMappings;
	static KeywordMappings<KeywordType::Requirements> requirementsKeywordMappings;
	static LocalizedKeywordMappings<KeywordType::Requirements> localizedRequirementsKeywordMappings;

	// Static members for storing styles
	static TooltipStyle contextTooltipStyle;
	static TooltipStyle categoryTooltipStyle;
	static TooltipStyle requirementsTooltipStyle;

	// Helper method to parse style configuration
	static TooltipStyle parseStyleConfig(const QString& styleConfig);

	// Helper methods for parsing mappings
	template<KeywordType Type>
	static KeywordMappings<Type> parseKeywordMappings(const QString& value);

	// Enhanced processKeywordMappings with styling support
	template<typename KeywordInfoType>
	static void processKeywordMappings(
		const QString& displayText,
		const QList<KeywordInfoType>& effectiveMappings,
		const QString& labelText,
		const QString& labelStyle,
		const QString& valuePrefix,
		const TooltipStyle& textStyle,
		QString& tooltip)
	{
		QStringList typeLabels;

		// Create a temporary collection of all matched keywords with their info
		QList<QPair<QString, QString>> matchedKeywords; // keyword, displayName
		QHash<QString, QString> keywordActions; // keyword -> action

		// Collect all matched keywords and their actions
		for (const KeywordInfoType& keywordInfo : effectiveMappings) {
			if (displayText.contains(keywordInfo.keyword)) {
				matchedKeywords.append(qMakePair(keywordInfo.keyword, keywordInfo.displayName));
				if (!keywordInfo.action.isEmpty()) {
					keywordActions.insert(keywordInfo.keyword, keywordInfo.action);
				}
			}
		}

		// Process each matched keyword to determine if it should be shown
		for (const auto& pair : matchedKeywords) {
			const QString& keyword = pair.first;
			const QString& displayName = pair.second;
			bool isHidden = false;

			// Check if this keyword should be hidden (by itself or others)

			// 1. Check if it hides itself (its action contains itself)
			if (keywordActions.contains(keyword) &&
				keywordActions[keyword].contains(keyword)) {
				isHidden = true;
			}

			// 2. Check if any other keyword's action hides this one
			if (!isHidden) {
				for (auto it = keywordActions.constBegin(); it != keywordActions.constEnd(); ++it) {
					// Skip checking against itself
					if (it.key() == keyword)
						continue;

					// If any character in another keyword's action matches this keyword, hide it
					for (const QChar& c : it.value()) {
						if (QString(c) == keyword) {
							isHidden = true;
							break;
						}
					}

					if (isHidden)
						break;
				}
			}

			// Add to display labels if not hidden
			if (!isHidden && !displayName.isEmpty()) {
				typeLabels.append(displayName);
			}
		}

		// Only display if we have labels to show
		if (!typeLabels.isEmpty()) {
			QString typeText = typeLabels.join(" + ");

			// Apply styling to label if specified
			QString styledLabelStyle = labelStyle;
			QString labelStyling = textStyle.toHtmlStyle();
			if (!labelStyling.isEmpty()) {
				// Merge with existing labelStyle
				if (labelStyle.contains("style='")) {
					styledLabelStyle = labelStyle;
					styledLabelStyle.replace("style='", labelStyling.mid(0, labelStyling.length() - 1) + ";");
				}
				else {
					styledLabelStyle += " " + labelStyling;
				}
			}

			tooltip += "<tr><td " + styledLabelStyle + ">" + labelText + "</td>";

			// Apply styling to value text
			QString valueStyleStr = textStyle.toHtmlStyle();
			if (!valueStyleStr.isEmpty()) {
				tooltip += "<td " + valueStyleStr + ">" + valuePrefix + typeText + "</td></tr>";
			}
			else {
				tooltip += "<td>" + valuePrefix + typeText + "</td></tr>";
			}
		}
	}
};
