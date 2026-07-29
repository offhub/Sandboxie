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
		100,
		0,
		100000,
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
	{ QT_TRANSLATE_NOOP("COptionsWindow", "Default"), { 50, 1024, 10000, 0, 100, 60000 } },
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
	bool HasGlobalOverride = false;
	int LocalValue = 0;
	int OriginalLocalValue = 0;
	bool HasLocalOverride = false;
	bool OriginalHasLocalOverride = false;
	QSpinBox* pSpin = nullptr;
};

struct SDeleteV3TargetState
{
	QString Prefix;
	QString PresetKey;
	int GlobalPreset = 1;
	int LocalPreset = 1;
	int OriginalLocalPreset = 1;
	bool HasLocalPresetOverride = false;
	bool OriginalHasLocalPresetOverride = false;
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
		QMap<QString, QString> BoxPresetValues;
		QSet<QString> BoxPresetResetKeys;
		QSet<QString> GlobalPresetResetKeys;
		bool AutoCompactV3 = false;
		bool AutoCompactV3Changed = false;
	};

	CDeleteV3AdvancedDialog(
		const QSharedPointer<CSbieIni>& pBox,
		const QMap<QString, int>& pendingOverrideValues,
		const QSet<QString>& pendingBoxResetKeys,
		const QSet<QString>& pendingGlobalResetKeys,
		const QMap<QString, QString>& pendingPresetValues,
		const QSet<QString>& pendingPresetResetKeys,
		const QSet<QString>& pendingGlobalPresetResetKeys,
		bool pendingAutoCompactV3,
		bool pendingAutoCompactV3Changed,
		QWidget* parent = nullptr)
		: QDialog(parent)
	{
		const QString BoxName = pBox ? pBox->GetName() : QString();
		const QString BaseTitle = COptionsWindow::tr("Delete V3 Advanced Settings");
		setWindowTitle(BoxName.isEmpty()
			? BaseTitle
			: BaseTitle + " - " + BoxName);

		QVBoxLayout* pMainLayout = new QVBoxLayout(this);
		QLabel* pIntro = new QLabel(COptionsWindow::tr("Tune Delete V3 journaling for this box. A preset provides the base values; edited values remain individual box overrides."), this);
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

		InitializeTarget(m_FileTarget, pBox, "FileDeleteV3", pendingOverrideValues, pendingBoxResetKeys, pendingGlobalResetKeys, pendingPresetValues, pendingPresetResetKeys, pendingGlobalPresetResetKeys);
		InitializeTarget(m_RegTarget, pBox, "RegDeleteV3", pendingOverrideValues, pendingBoxResetKeys, pendingGlobalResetKeys, pendingPresetValues, pendingPresetResetKeys, pendingGlobalPresetResetKeys);
		m_AutoCompactV3 = pendingAutoCompactV3Changed ? pendingAutoCompactV3 : pBox->GetBool("AutoCompactV3", false);
		m_OriginalAutoCompactV3 = pBox->GetBool("AutoCompactV3", false);
		m_AutoCompactV3Changed = pendingAutoCompactV3Changed;

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
		Result.AutoCompactV3 = m_AutoCompactV3;
		Result.AutoCompactV3Changed = m_AutoCompactV3Changed;
		return Result;
	}

private:
	void InitializeTarget(
		SDeleteV3TargetState& Target,
		const QSharedPointer<CSbieIni>& pBox,
		const QString& Prefix,
		const QMap<QString, int>& pendingOverrideValues,
		const QSet<QString>& pendingBoxResetKeys,
		const QSet<QString>& pendingGlobalResetKeys,
		const QMap<QString, QString>& pendingPresetValues,
		const QSet<QString>& pendingPresetResetKeys,
		const QSet<QString>& pendingGlobalPresetResetKeys)
	{
		Target.Prefix = Prefix;
		Target.PresetKey = Prefix + "Preset";
		Target.ResetGlobalRequested = false;

		auto PresetIndex = [](const QString& Name) {
			for (int i = 1; i < g_DeleteV3PresetCount; ++i) {
				QString ConfigName = QString::fromLatin1(g_DeleteV3Presets[i].NameNoop);
				ConfigName.remove(' ');
				if (Name.compare(ConfigName, Qt::CaseInsensitive) == 0)
					return i;
			}
			return 1;
		};
		QString GlobalPresetText = theAPI->GetGlobalSettings()->GetText(Target.PresetKey);
		Target.GlobalPreset = PresetIndex(GlobalPresetText);
		QString LocalPresetText = pBox->GetText(Target.PresetKey);
		Target.HasLocalPresetOverride = !LocalPresetText.isNull() && !LocalPresetText.isEmpty();
		Target.OriginalHasLocalPresetOverride = Target.HasLocalPresetOverride;
		Target.LocalPreset = Target.HasLocalPresetOverride ? PresetIndex(LocalPresetText) : Target.GlobalPreset;
		Target.OriginalLocalPreset = Target.LocalPreset;
		if (pendingPresetResetKeys.contains(Target.PresetKey))
			Target.HasLocalPresetOverride = false;
		if (pendingPresetValues.contains(Target.PresetKey)) {
			Target.HasLocalPresetOverride = true;
			Target.LocalPreset = PresetIndex(pendingPresetValues.value(Target.PresetKey));
		}
		if (pendingGlobalPresetResetKeys.contains(Target.PresetKey))
			Target.ResetGlobalRequested = true;

		for (int i = 0; i < g_DeleteV3SettingCount; ++i) {
			const QString Key = COptionsWindow__DeleteV3Key(Prefix, i);
			const SDeleteV3SettingSpec& Spec = g_DeleteV3SettingSpecs[i];

			QString GlobalText = theAPI->GetGlobalSettings()->GetText(Key);
			bool ok = false;
			int GlobalValue = GlobalText.toInt(&ok);
			bool HasGlobalOverride = ok;
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
			State.HasGlobalOverride = HasGlobalOverride;
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
		SDeleteV3TargetState* pTarget = &Target;

		QWidget* pPage = new QWidget(pTabs);
		QVBoxLayout* pLayout = new QVBoxLayout(pPage);

		QLabel* pHint = new QLabel(COptionsWindow::tr("A preset is stored as one box setting. Individual settings override the preset and are highlighted. Changing a preset does not reset those overrides."), pPage);
		pHint->setWordWrap(true);
		pLayout->addWidget(pHint);

		QHBoxLayout* pPresetLayout = new QHBoxLayout();
		QLabel* pPresetLabel = new QLabel(COptionsWindow::tr("Preset"), pPage);
		pTarget->pPresetCombo = new QComboBox(pPage);
		pTarget->pPresetCombo->setMaxVisibleItems(g_DeleteV3PresetCount);
		for (int i = 0; i < g_DeleteV3PresetCount; ++i)
			pTarget->pPresetCombo->addItem(COptionsWindow::tr(g_DeleteV3Presets[i].NameNoop));

		QPushButton* pResetBox = new QPushButton(COptionsWindow::tr("Reset Box"), pPage);
		QPushButton* pResetGlobal = new QPushButton(COptionsWindow::tr("Clear Global Settings"), pPage);
		pResetBox->setToolTip(COptionsWindow::tr("Remove the box-specific Delete V3 preset and individual settings for this tab when you save the options."));
		pResetGlobal->setToolTip(COptionsWindow::tr("Clear shared global settings for this tab when the main Options dialog is saved. This affects all boxes that inherit global settings; boxes with local overrides keep their own values."));

		pPresetLayout->addWidget(pPresetLabel);
		pPresetLayout->addWidget(pTarget->pPresetCombo, 1);
		pPresetLayout->addWidget(pResetBox);
		pPresetLayout->addWidget(pResetGlobal);
		pLayout->addLayout(pPresetLayout);

		QFormLayout* pFormLayout = new QFormLayout();
		for (int i = 0; i < pTarget->Settings.size(); ++i) {
			SDeleteV3SettingState& Setting = pTarget->Settings[i];
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

			connect(pSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this, pTarget, i](int Value) {
				pTarget->Settings[i].HasLocalOverride = true;
				pTarget->Settings[i].LocalValue = Value;
				RefreshTarget(*pTarget);
			});

			QWidget* pSpinRow = new QWidget(pPage);
			QHBoxLayout* pSpinRowLayout = new QHBoxLayout(pSpinRow);
			pSpinRowLayout->setContentsMargins(0, 0, 0, 0);
			pSpinRowLayout->addWidget(pSpin, 1);
			QPushButton* pMaxButton = new QPushButton(COptionsWindow::tr("Max"), pSpinRow);
			pMaxButton->setToolTip(COptionsWindow::tr("Set this value to its maximum allowed value."));
			pMaxButton->setMaximumWidth(pMaxButton->sizeHint().width());
			connect(pMaxButton, &QPushButton::clicked, this, [this, pTarget, i, Spec]() {
				pTarget->Settings[i].HasLocalOverride = true;
				pTarget->Settings[i].LocalValue = Spec.MaxValue;
				RefreshTarget(*pTarget);
			});
			pSpinRowLayout->addWidget(pMaxButton);
			pFormLayout->addRow(COptionsWindow::tr(Spec.LabelNoop), pSpinRow);
		}
		pLayout->addLayout(pFormLayout);

		pTarget->pStatusLabel = new QLabel(pPage);
		pTarget->pStatusLabel->setWordWrap(true);
		pLayout->addWidget(pTarget->pStatusLabel);
		if (Target.Prefix == "FileDeleteV3") {
			QCheckBox* pAutoCompact = new QCheckBox(COptionsWindow::tr("Automatically compact Delete V3 metadata when the box closes"), pPage);
			pAutoCompact->setToolTip(COptionsWindow::tr("Compacts V3 metadata after the last sandboxed process exits. It is skipped when AutoDelete or AutoRemove is enabled, and while the box is being deleted."));
			pAutoCompact->setChecked(m_AutoCompactV3);
			connect(pAutoCompact, &QCheckBox::toggled, this, [this](bool Checked) {
				m_AutoCompactV3 = Checked;
				m_AutoCompactV3Changed = Checked != m_OriginalAutoCompactV3;
			});
			pLayout->addWidget(pAutoCompact);
		}
		pLayout->addStretch(1);

		connect(pTarget->pPresetCombo, QOverload<int>::of(&QComboBox::activated), this, [this, pTarget](int Index) {
			ApplyPreset(*pTarget, Index);
		});

		connect(pResetBox, &QPushButton::clicked, this, [this, pTarget]() {
			for (SDeleteV3SettingState& Setting : pTarget->Settings)
				Setting.HasLocalOverride = false;
			pTarget->HasLocalPresetOverride = false;
			RefreshTarget(*pTarget);
		});

		connect(pResetGlobal, &QPushButton::clicked, this, [this, pTarget]() {
			pTarget->ResetGlobalRequested = !pTarget->ResetGlobalRequested;
			RefreshTarget(*pTarget);
		});

		RefreshTarget(*pTarget);
		pTabs->addTab(pPage, Title);
	}

	void ApplyPreset(SDeleteV3TargetState& Target, int Index)
	{
		if (Index < 0 || Index >= g_DeleteV3PresetCount)
			return;

		Target.HasLocalPresetOverride = Index > 0;
		Target.LocalPreset = Index > 0 ? Index : Target.GlobalPreset;
		RefreshTarget(Target);
	}

	int EffectiveValue(const SDeleteV3TargetState& Target, const SDeleteV3SettingState& Setting, int index) const
	{
		if (Setting.HasLocalOverride)
			return Setting.LocalValue;
		if (Setting.HasGlobalOverride && !Target.ResetGlobalRequested)
			return Setting.GlobalValue;
		if (Target.ResetGlobalRequested)
			return g_DeleteV3SettingSpecs[index].DefaultValue;
		const int Preset = Target.HasLocalPresetOverride ? Target.LocalPreset : Target.GlobalPreset;
		return g_DeleteV3Presets[Preset].Values[index];
	}

	void RefreshTarget(SDeleteV3TargetState& Target)
	{
		// Guards are necessary: CreateTab assigns pStatusLabel *after* the spin
		// creation loop, but each spin's valueChanged is already wired to this
		// function. If setRange() ever clamps a value (e.g. MinValue > 0) a
		// valueChanged fires mid-loop before all widgets exist.
		if (!Target.pPresetCombo || !Target.pStatusLabel)
			return;

		for (int i = 0; i < Target.Settings.size(); ++i) {
			SDeleteV3SettingState& Setting = Target.Settings[i];
			if (!Setting.pSpin)
				continue;
			int Value = EffectiveValue(Target, Setting, i);
			Setting.pSpin->blockSignals(true);
			Setting.pSpin->setValue(Value);
			Setting.pSpin->blockSignals(false);
			const bool IsOverride = Setting.HasLocalOverride || (Setting.HasGlobalOverride && !Target.ResetGlobalRequested);
			Setting.pSpin->setStyleSheet(IsOverride ? QStringLiteral("QSpinBox { background-color: #fff3cd; }") : QString());
			if (IsOverride)
				Setting.pSpin->setToolTip(COptionsWindow::tr("This individual setting overrides the selected Delete V3 preset. ") + COptionsWindow::tr(g_DeleteV3SettingSpecs[i].ToolTipNoop));
			else
				Setting.pSpin->setToolTip(COptionsWindow::tr(g_DeleteV3SettingSpecs[i].ToolTipNoop));
		}

		Target.pPresetCombo->blockSignals(true);
		Target.pPresetCombo->setCurrentIndex(Target.HasLocalPresetOverride ? Target.LocalPreset : Target.GlobalPreset);
		Target.pPresetCombo->blockSignals(false);

		QStringList Actions;
		if (Target.ResetGlobalRequested)
			Actions << COptionsWindow::tr("shared global defaults will be cleared on main save");

		bool HasIndividualOverrides = false;
		for (const SDeleteV3SettingState& Setting : qAsConst(Target.Settings)) {
			if (Setting.HasLocalOverride || (Setting.HasGlobalOverride && !Target.ResetGlobalRequested)) {
				HasIndividualOverrides = true;
				break;
			}
		}
		const int Preset = Target.HasLocalPresetOverride ? Target.LocalPreset : Target.GlobalPreset;
		Actions << COptionsWindow::tr("preset: %1").arg(COptionsWindow::tr(g_DeleteV3Presets[Preset].NameNoop));
		if (HasIndividualOverrides)
			Actions << COptionsWindow::tr("individual overrides are active");
		else
			Actions << COptionsWindow::tr("box inherits global/default values");

		Target.pStatusLabel->setText(COptionsWindow::tr("Status: %1.").arg(Actions.join(COptionsWindow::tr(", "))));
	}

	void AppendResult(const SDeleteV3TargetState& Target, SResult& Result) const
	{
		if (Target.HasLocalPresetOverride) {
			if (!Target.OriginalHasLocalPresetOverride || Target.LocalPreset != Target.OriginalLocalPreset) {
				QString PresetName = QString::fromLatin1(g_DeleteV3Presets[Target.LocalPreset].NameNoop);
				PresetName.remove(' ');
				Result.BoxPresetValues.insert(Target.PresetKey, PresetName);
			}
		} else if (Target.OriginalHasLocalPresetOverride) {
			Result.BoxPresetResetKeys.insert(Target.PresetKey);
		}

		if (Target.ResetGlobalRequested)
			Result.GlobalPresetResetKeys.insert(Target.PresetKey);

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
	bool m_AutoCompactV3 = false;
	bool m_OriginalAutoCompactV3 = false;
	bool m_AutoCompactV3Changed = false;
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
	QVector<QPair<QAbstractButton*, bool>> ButtonStates;
	if (ui.buttonBox) {
		const QList<QAbstractButton*> Buttons = ui.buttonBox->buttons();
		ButtonStates.reserve(Buttons.size());
		for (QAbstractButton* pButton : Buttons) {
			if (!pButton)
				continue;
			ButtonStates.append(qMakePair(pButton, pButton->isEnabled()));
			pButton->setEnabled(false);
		}
	}

	CDeleteV3AdvancedDialog Dialog(m_pBox, m_DeleteV3BoxOverrideValues, m_DeleteV3BoxResetKeys, m_DeleteV3GlobalResetKeys, m_DeleteV3BoxPresetValues, m_DeleteV3BoxPresetResetKeys, m_DeleteV3GlobalPresetResetKeys, m_AutoCompactV3, m_AutoCompactV3Changed, this);
	const int Ret = theGUI->SafeExec(&Dialog);

	for (const auto& State : qAsConst(ButtonStates)) {
		if (State.first)
			State.first->setEnabled(State.second);
	}

	if (Ret != QDialog::Accepted)
		return;

	CDeleteV3AdvancedDialog::SResult Result = Dialog.GetResult();
	m_DeleteV3BoxOverrideValues = Result.BoxOverrideValues;
	m_DeleteV3BoxResetKeys = Result.BoxResetKeys;
	m_DeleteV3GlobalResetKeys = Result.GlobalResetKeys;
	m_DeleteV3BoxPresetValues = Result.BoxPresetValues;
	m_DeleteV3BoxPresetResetKeys = Result.BoxPresetResetKeys;
	m_DeleteV3GlobalPresetResetKeys = Result.GlobalPresetResetKeys;
	m_AutoCompactV3 = Result.AutoCompactV3;
	m_AutoCompactV3Changed = Result.AutoCompactV3Changed;
	m_GeneralChanged = true;
	OnOptChanged();
}

void COptionsWindow::SaveDeleteV3AdvancedSettings()
{
	if (m_AutoCompactV3Changed) {
		if (m_AutoCompactV3)
			m_pBox->SetBool("AutoCompactV3", true);
		else
			m_pBox->DelValue("AutoCompactV3");
	}
	for (const QString& Key : qAsConst(m_DeleteV3BoxPresetResetKeys))
		m_pBox->DelValue(Key);

	for (auto I = m_DeleteV3BoxPresetValues.constBegin(); I != m_DeleteV3BoxPresetValues.constEnd(); ++I)
		m_pBox->SetText(I.key(), I.value());

	for (const QString& Key : qAsConst(m_DeleteV3GlobalPresetResetKeys))
		theAPI->GetGlobalSettings()->DelValue(Key);

	for (auto I = m_DeleteV3BoxResetKeys.constBegin(); I != m_DeleteV3BoxResetKeys.constEnd(); ++I)
		m_pBox->DelValue(*I);

	for (auto I = m_DeleteV3BoxOverrideValues.constBegin(); I != m_DeleteV3BoxOverrideValues.constEnd(); ++I)
		m_pBox->SetNum(I.key(), I.value());

	for (auto I = m_DeleteV3GlobalResetKeys.constBegin(); I != m_DeleteV3GlobalResetKeys.constEnd(); ++I)
		theAPI->GetGlobalSettings()->DelValue(*I);

	m_DeleteV3BoxOverrideValues.clear();
	m_DeleteV3BoxResetKeys.clear();
	m_DeleteV3GlobalResetKeys.clear();
	m_DeleteV3BoxPresetValues.clear();
	m_DeleteV3BoxPresetResetKeys.clear();
	m_DeleteV3GlobalPresetResetKeys.clear();
	m_AutoCompactV3Changed = false;
}
