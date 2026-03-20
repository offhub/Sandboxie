#include "stdafx.h"
#include "OptionsWindow.h"
#include "SandMan.h"

namespace {

struct SDeleteV3SettingSpec
{
	const char* Suffix;
	const char* LabelNoop;
	int DefaultValue;
	int MinValue;
	int MaxValue;
	const char* ToolTipNoop;
	const char* UnitSuffixNoop;
};

struct SDeleteV3Preset
{
	const char* NameNoop;
	int Values[6];
};

static const SDeleteV3SettingSpec g_DeleteV3SettingSpecs[] = {
	{
		"RefreshDebounceMs",
		QT_TRANSLATE_NOOP("COptionsWindow", "Refresh debounce"),
		50,
		0,
		5000,
		QT_TRANSLATE_NOOP("COptionsWindow", "Debounce window before the V3 path tree is refreshed from journal updates."),
		QT_TRANSLATE_NOOP("COptionsWindow", " ms")
	},
	{
		"JournalMaxSizeKB",
		QT_TRANSLATE_NOOP("COptionsWindow", "Journal size limit"),
		1024,
		0,
		512 * 1024,
		QT_TRANSLATE_NOOP("COptionsWindow", "Maximum journal size before compaction into the .dat file is triggered."),
		QT_TRANSLATE_NOOP("COptionsWindow", " KB")
	},
	{
		"JournalMaxLines",
		QT_TRANSLATE_NOOP("COptionsWindow", "Journal line limit"),
		10000,
		0,
		100000000,
		QT_TRANSLATE_NOOP("COptionsWindow", "Maximum number of incremental journal entries before compaction is triggered."),
		QT_TRANSLATE_NOOP("COptionsWindow", " lines")
	},
	{
		"JournalKeepOpenMs",
		QT_TRANSLATE_NOOP("COptionsWindow", "Keep journal open"),
		0,
		0,
		60000,
		QT_TRANSLATE_NOOP("COptionsWindow", "Keep the append handle open for a short time to reduce reopen overhead during bursts."),
		QT_TRANSLATE_NOOP("COptionsWindow", " ms")
	},
	{
		"CompactionBusyWritesPerSec",
		QT_TRANSLATE_NOOP("COptionsWindow", "Busy threshold"),
		200,
		0,
		1000000,
		QT_TRANSLATE_NOOP("COptionsWindow", "Writes per second threshold that marks the journal as busy and defers compaction."),
		QT_TRANSLATE_NOOP("COptionsWindow", " writes/s")
	},
	{
		"CompactionBusyHoldMs",
		QT_TRANSLATE_NOOP("COptionsWindow", "Busy hold window"),
		60000,
		0,
		300000,
		QT_TRANSLATE_NOOP("COptionsWindow", "How long compaction remains deferred after a busy burst is detected."),
		QT_TRANSLATE_NOOP("COptionsWindow", " ms")
	}
};

static const SDeleteV3Preset g_DeleteV3Presets[] = {
	{ QT_TRANSLATE_NOOP("COptionsWindow", "Current / Custom"), { 0, 0, 0, 0, 0, 0 } },
	{ QT_TRANSLATE_NOOP("COptionsWindow", "Default"), { 50, 1024, 10000, 0, 200, 60000 } },
	{ QT_TRANSLATE_NOOP("COptionsWindow", "Low Latency"), { 25, 512, 5000, 5000, 100, 30000 } },
	{ QT_TRANSLATE_NOOP("COptionsWindow", "Low IO"), { 100, 2048, 15000, 60000, 300, 90000 } },
	{ QT_TRANSLATE_NOOP("COptionsWindow", "Write Heavy"), { 250, 25600, 100000, 60000, 600, 120000 } }
};

static const int g_DeleteV3SettingCount = sizeof(g_DeleteV3SettingSpecs) / sizeof(g_DeleteV3SettingSpecs[0]);
static const int g_DeleteV3PresetCount = sizeof(g_DeleteV3Presets) / sizeof(g_DeleteV3Presets[0]);
static_assert(sizeof(g_DeleteV3Presets[0].Values) / sizeof(g_DeleteV3Presets[0].Values[0]) == sizeof(g_DeleteV3SettingSpecs) / sizeof(g_DeleteV3SettingSpecs[0]),
	"SDeleteV3Preset::Values array size must match g_DeleteV3SettingSpecs count");

static QString COptionsWindow__DeleteV3Key(const QString& prefix, int index)
{
	return prefix + g_DeleteV3SettingSpecs[index].Suffix;
}

struct SDeleteV3SettingState
{
	QString Key;
	int GlobalValue = 0;
	int LocalValue = 0;
	int OriginalLocalValue = 0;
	bool HasLocalOverride = false;
	bool OriginalHasLocalOverride = false;
	QSpinBox* pSpin = nullptr;
};

struct SDeleteV3TargetState
{
	QString Prefix;
	QVector<SDeleteV3SettingState> Settings;
	QLabel* pStatusLabel = nullptr;
	QComboBox* pPresetCombo = nullptr;
	bool ResetGlobalRequested = false;
};

class CDeleteV3AdvancedDialog : public QDialog
{
public:
	struct SResult
	{
		QMap<QString, int> BoxOverrideValues;
		QSet<QString> BoxResetKeys;
		QSet<QString> GlobalResetKeys;
	};

	CDeleteV3AdvancedDialog(
		const QSharedPointer<CSbieIni>& pBox,
		const QMap<QString, int>& pendingOverrideValues,
		const QSet<QString>& pendingBoxResetKeys,
		const QSet<QString>& pendingGlobalResetKeys,
		QWidget* parent = nullptr)
		: QDialog(parent)
	{
		setWindowTitle(COptionsWindow::tr("Delete V3 Advanced Settings"));

		QVBoxLayout* pMainLayout = new QVBoxLayout(this);
		QLabel* pIntro = new QLabel(COptionsWindow::tr("Tune Delete V3 journaling for this box. Presets and value edits create box-specific overrides."), this);
		pIntro->setWordWrap(true);
		pMainLayout->addWidget(pIntro);
		QLabel* pSaveHint = new QLabel(COptionsWindow::tr("Dialog OK button stages changes only. Use Apply or OK in the main Options window to persist them."), this);
		pSaveHint->setWordWrap(true);
		pMainLayout->addWidget(pSaveHint);
		QLabel* pGlobalHint = new QLabel(COptionsWindow::tr("Clear Global Settings affects all boxes that inherit global Delete V3 values. Box-specific overrides are not removed by this action."), this);
		pGlobalHint->setWordWrap(true);
		pMainLayout->addWidget(pGlobalHint);

		QTabWidget* pTabs = new QTabWidget(this);
		pMainLayout->addWidget(pTabs, 1);

		InitializeTarget(m_FileTarget, pBox, "FileDeleteV3", pendingOverrideValues, pendingBoxResetKeys, pendingGlobalResetKeys);
		InitializeTarget(m_RegTarget, pBox, "RegDeleteV3", pendingOverrideValues, pendingBoxResetKeys, pendingGlobalResetKeys);

		CreateTab(pTabs, m_FileTarget, COptionsWindow::tr("File"));
		CreateTab(pTabs, m_RegTarget, COptionsWindow::tr("Registry"));

		QDialogButtonBox* pButtons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
		if (QPushButton* pOk = pButtons->button(QDialogButtonBox::Ok))
			pOk->setText(COptionsWindow::tr("OK (Stage)"));
		connect(pButtons, &QDialogButtonBox::accepted, this, &QDialog::accept);
		connect(pButtons, &QDialogButtonBox::rejected, this, &QDialog::reject);
		pMainLayout->addWidget(pButtons);

		adjustSize();
		QScreen* pScreen = QGuiApplication::primaryScreen();
		if (pScreen) {
			QSize maxSize = pScreen->availableGeometry().size() * 0.85;
			resize(sizeHint().boundedTo(maxSize));
		}
	}

	SResult GetResult() const
	{
		SResult Result;
		AppendResult(m_FileTarget, Result);
		AppendResult(m_RegTarget, Result);
		return Result;
	}

private:
	void InitializeTarget(
		SDeleteV3TargetState& Target,
		const QSharedPointer<CSbieIni>& pBox,
		const QString& Prefix,
		const QMap<QString, int>& pendingOverrideValues,
		const QSet<QString>& pendingBoxResetKeys,
		const QSet<QString>& pendingGlobalResetKeys)
	{
		Target.Prefix = Prefix;
		Target.ResetGlobalRequested = false;

		for (int i = 0; i < g_DeleteV3SettingCount; ++i) {
			const QString Key = COptionsWindow__DeleteV3Key(Prefix, i);
			const SDeleteV3SettingSpec& Spec = g_DeleteV3SettingSpecs[i];

			QString GlobalText = theAPI->GetGlobalSettings()->GetText(Key);
			bool ok = false;
			int GlobalValue = GlobalText.toInt(&ok);
			if (!ok)
				GlobalValue = Spec.DefaultValue;

			QString LocalText = pBox->GetText(Key);
			ok = false;
			int LocalValue = LocalText.toInt(&ok);
			bool HasLocalOverride = !LocalText.isNull() && ok;
			bool OriginalHasLocalOverride = HasLocalOverride;
			int OriginalLocalValue = HasLocalOverride ? LocalValue : GlobalValue;
			if (!HasLocalOverride)
				LocalValue = GlobalValue;

			if (pendingBoxResetKeys.contains(Key))
				HasLocalOverride = false;
			if (pendingOverrideValues.contains(Key)) {
				HasLocalOverride = true;
				LocalValue = pendingOverrideValues.value(Key);
			}

			SDeleteV3SettingState State;
			State.Key = Key;
			State.GlobalValue = GlobalValue;
			State.LocalValue = LocalValue;
			State.OriginalLocalValue = OriginalLocalValue;
			State.HasLocalOverride = HasLocalOverride;
			State.OriginalHasLocalOverride = OriginalHasLocalOverride;
			Target.Settings.append(State);
		}

		for (int i = 0; i < g_DeleteV3SettingCount; ++i) {
			if (pendingGlobalResetKeys.contains(COptionsWindow__DeleteV3Key(Prefix, i))) {
				Target.ResetGlobalRequested = true;
				break;
			}
		}
	}

	void CreateTab(QTabWidget* pTabs, SDeleteV3TargetState& Target, const QString& Title)
	{
		QWidget* pPage = new QWidget(pTabs);
		QVBoxLayout* pLayout = new QVBoxLayout(pPage);

		QLabel* pHint = new QLabel(COptionsWindow::tr("Presets apply to box overrides only. Reset Box removes the per-box keys. Reset Global clears the corresponding global settings when the options dialog is saved."), pPage);
		pHint->setWordWrap(true);
		pLayout->addWidget(pHint);

		QHBoxLayout* pPresetLayout = new QHBoxLayout();
		QLabel* pPresetLabel = new QLabel(COptionsWindow::tr("Preset"), pPage);
		Target.pPresetCombo = new QComboBox(pPage);
		Target.pPresetCombo->setMaxVisibleItems(g_DeleteV3PresetCount);
		for (int i = 0; i < g_DeleteV3PresetCount; ++i)
			Target.pPresetCombo->addItem(COptionsWindow::tr(g_DeleteV3Presets[i].NameNoop));

		QPushButton* pResetBox = new QPushButton(COptionsWindow::tr("Reset Box"), pPage);
		QPushButton* pResetGlobal = new QPushButton(COptionsWindow::tr("Clear Global Settings"), pPage);
		pResetBox->setToolTip(COptionsWindow::tr("Remove all box-specific Delete V3 settings for this tab when you save the options."));
		pResetGlobal->setToolTip(COptionsWindow::tr("Clear shared global settings for this tab when the main Options dialog is saved. This affects all boxes that inherit global settings; boxes with local overrides keep their own values."));

		pPresetLayout->addWidget(pPresetLabel);
		pPresetLayout->addWidget(Target.pPresetCombo, 1);
		pPresetLayout->addWidget(pResetBox);
		pPresetLayout->addWidget(pResetGlobal);
		pLayout->addLayout(pPresetLayout);

		QFormLayout* pFormLayout = new QFormLayout();
		for (int i = 0; i < Target.Settings.size(); ++i) {
			SDeleteV3SettingState& Setting = Target.Settings[i];
			const SDeleteV3SettingSpec& Spec = g_DeleteV3SettingSpecs[i];

			QSpinBox* pSpin = new QSpinBox(pPage);
			pSpin->setRange(Spec.MinValue, Spec.MaxValue);
			pSpin->setSuffix(COptionsWindow::tr(Spec.UnitSuffixNoop));
			pSpin->setToolTip(COptionsWindow::tr(Spec.ToolTipNoop));
			if (QString::fromLatin1(Spec.Suffix).contains("Lines"))
				pSpin->setSingleStep(1000);
			else if (QString::fromLatin1(Spec.Suffix).contains("Size"))
				pSpin->setSingleStep(256);
			else if (QString::fromLatin1(Spec.Suffix).contains("Hold") || QString::fromLatin1(Spec.Suffix).contains("KeepOpen") || QString::fromLatin1(Spec.Suffix).contains("Refresh"))
				pSpin->setSingleStep(25);
			else
				pSpin->setSingleStep(10);
			Setting.pSpin = pSpin;

			connect(pSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this, &Target, i](int Value) {
				Target.Settings[i].HasLocalOverride = true;
				Target.Settings[i].LocalValue = Value;
				RefreshTarget(Target);
			});

			pFormLayout->addRow(COptionsWindow::tr(Spec.LabelNoop), pSpin);
		}
		pLayout->addLayout(pFormLayout);

		Target.pStatusLabel = new QLabel(pPage);
		Target.pStatusLabel->setWordWrap(true);
		pLayout->addWidget(Target.pStatusLabel);
		pLayout->addStretch(1);

		connect(Target.pPresetCombo, QOverload<int>::of(&QComboBox::activated), this, [this, &Target](int Index) {
			if (Index <= 0)
				return;
			ApplyPreset(Target, Index);
		});

		connect(pResetBox, &QPushButton::clicked, this, [this, &Target]() {
			for (SDeleteV3SettingState& Setting : Target.Settings)
				Setting.HasLocalOverride = false;
			RefreshTarget(Target);
		});

		connect(pResetGlobal, &QPushButton::clicked, this, [this, &Target]() {
			Target.ResetGlobalRequested = !Target.ResetGlobalRequested;
			RefreshTarget(Target);
		});

		RefreshTarget(Target);
		pTabs->addTab(pPage, Title);
	}

	void ApplyPreset(SDeleteV3TargetState& Target, int Index)
	{
		if (Index <= 0 || Index >= g_DeleteV3PresetCount)
			return;

		for (int i = 0; i < Target.Settings.size(); ++i) {
			Target.Settings[i].HasLocalOverride = true;
			Target.Settings[i].LocalValue = g_DeleteV3Presets[Index].Values[i];
		}
		RefreshTarget(Target);
	}

	int EffectiveValue(const SDeleteV3TargetState& Target, const SDeleteV3SettingState& Setting, int index) const
	{
		if (Setting.HasLocalOverride)
			return Setting.LocalValue;
		if (Target.ResetGlobalRequested)
			return g_DeleteV3SettingSpecs[index].DefaultValue;
		return Setting.GlobalValue;
	}

	void RefreshTarget(SDeleteV3TargetState& Target)
	{
		for (int i = 0; i < Target.Settings.size(); ++i) {
			SDeleteV3SettingState& Setting = Target.Settings[i];
			int Value = EffectiveValue(Target, Setting, i);
			Setting.pSpin->blockSignals(true);
			Setting.pSpin->setValue(Value);
			Setting.pSpin->blockSignals(false);
		}

		// Auto-detect which preset matches current effective values
		int MatchedPreset = 0; // 0 = "Custom" (no match)
		for (int p = 1; p < g_DeleteV3PresetCount; ++p) {
			bool AllMatch = true;
			for (int i = 0; i < Target.Settings.size(); ++i) {
				if (EffectiveValue(Target, Target.Settings[i], i) != g_DeleteV3Presets[p].Values[i]) {
					AllMatch = false;
					break;
				}
			}
			if (AllMatch) {
				MatchedPreset = p;
				break;
			}
		}
		Target.pPresetCombo->blockSignals(true);
		Target.pPresetCombo->setCurrentIndex(MatchedPreset);
		Target.pPresetCombo->blockSignals(false);

		QStringList Actions;
		if (Target.ResetGlobalRequested)
			Actions << COptionsWindow::tr("shared global defaults will be cleared on main save");

		bool HasLocalOverrides = false;
		for (const SDeleteV3SettingState& Setting : qAsConst(Target.Settings)) {
			if (Setting.HasLocalOverride) {
				HasLocalOverrides = true;
				break;
			}
		}
		if (HasLocalOverrides)
			Actions << COptionsWindow::tr("custom box overrides are active");
		else
			Actions << COptionsWindow::tr("box inherits global/default values");

		Target.pStatusLabel->setText(COptionsWindow::tr("Status: %1.").arg(Actions.join(COptionsWindow::tr(", "))));
	}

	void AppendResult(const SDeleteV3TargetState& Target, SResult& Result) const
	{
		for (int i = 0; i < Target.Settings.size(); ++i) {
			const SDeleteV3SettingState& Setting = Target.Settings[i];
			if (Setting.HasLocalOverride) {
				if (!Setting.OriginalHasLocalOverride || Setting.LocalValue != Setting.OriginalLocalValue)
					Result.BoxOverrideValues.insert(Setting.Key, Setting.LocalValue);
			}
			else if (Setting.OriginalHasLocalOverride) {
				Result.BoxResetKeys.insert(Setting.Key);
			}

			if (Target.ResetGlobalRequested)
				Result.GlobalResetKeys.insert(Setting.Key);
		}
	}

	SDeleteV3TargetState m_FileTarget;
	SDeleteV3TargetState m_RegTarget;
};

} // namespace

void COptionsWindow::UpdateDeleteV3AdvancedButton()
{
	bool bEnabled = ui.cmbVersion->currentIndex() == 2;
	ui.btnDeleteV3Options->setEnabled(bEnabled);
	ui.btnDeleteV3Options->setToolTip(bEnabled
		? tr("Delete V3 advanced settings")
		: tr("Delete V3 advanced settings are available only when Version 3 is selected."));
}

void COptionsWindow::OnDeleteV3AdvancedSettings()
{
	CDeleteV3AdvancedDialog Dialog(m_pBox, m_DeleteV3BoxOverrideValues, m_DeleteV3BoxResetKeys, m_DeleteV3GlobalResetKeys, this);
	if (theGUI->SafeExec(&Dialog) != QDialog::Accepted)
		return;

	CDeleteV3AdvancedDialog::SResult Result = Dialog.GetResult();
	m_DeleteV3BoxOverrideValues = Result.BoxOverrideValues;
	m_DeleteV3BoxResetKeys = Result.BoxResetKeys;
	m_DeleteV3GlobalResetKeys = Result.GlobalResetKeys;
	m_GeneralChanged = true;
	OnOptChanged();
}

void COptionsWindow::SaveDeleteV3AdvancedSettings()
{
	for (auto I = m_DeleteV3BoxResetKeys.constBegin(); I != m_DeleteV3BoxResetKeys.constEnd(); ++I)
		m_pBox->DelValue(*I);

	for (auto I = m_DeleteV3BoxOverrideValues.constBegin(); I != m_DeleteV3BoxOverrideValues.constEnd(); ++I)
		m_pBox->SetNum(I.key(), I.value());

	for (auto I = m_DeleteV3GlobalResetKeys.constBegin(); I != m_DeleteV3GlobalResetKeys.constEnd(); ++I)
		theAPI->GetGlobalSettings()->DelValue(*I);

	m_DeleteV3BoxOverrideValues.clear();
	m_DeleteV3BoxResetKeys.clear();
	m_DeleteV3GlobalResetKeys.clear();
}