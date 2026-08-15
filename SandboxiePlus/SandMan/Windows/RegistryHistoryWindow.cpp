/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "stdafx.h"
#include "RegistryHistoryWindow.h"
#include "../SandMan.h"
#include "../../MiscHelpers/Common/Finder.h"
#include "../../MiscHelpers/Common/PanelView.h"
#include "../../MiscHelpers/Common/CheckableMessageBox.h"
#include "../../QSbieAPI/SbieUtils.h"

#include <QAbstractButton>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFormLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QSet>
#include <QSpinBox>
#include <QTimer>
#include <QTreeWidget>
#include <QToolButton>
#include <QVBoxLayout>

#include <windows.h>
#include <shellapi.h>

namespace
{
    const quint32 DeleteValueType = 0x786F6273;
    const quint64 DeleteKeyTime =
        (quint64(0x01B01234) << 32) | quint64(0xDEAD44A0);
    const quint64 MaxCompareData = sizeof(void*) == 4
        ? 128ULL * 1024 * 1024 : 512ULL * 1024 * 1024;
    const int MaxCompareEntries = sizeof(void*) == 4 ? 250000 : 1000000;
    const int MaxDisplayedChanges = 50000;
    const int MaxGeneratedFilterLength = 64 * 1024;

    enum ERegistryHistoryRole
    {
        eCanonicalPath = Qt::UserRole,
        eChangeCategory
    };

    enum EChangeCategory
    {
        eAdded,
        eDeleted,
        eModified,
        eDateOnly
    };

    enum EFilterField
    {
        eAllFields,
        eChangeField,
        ePathField,
        eValueField,
        eTypeField,
        eDataField,
        eDateField
    };

    struct SRegistryValue
    {
        QString Name;
        DWORD Type = REG_NONE;
        QByteArray Data;
    };

    struct SRegistryKey
    {
        QString Path;
        quint64 LastWrite = 0;
        QMap<QString, SRegistryValue> Values;
    };

    struct SRegistryDeletion
    {
        QString Kind;
        QString Path;
        QString Value;
    };

    struct SRegistryState
    {
        QMap<QString, SRegistryKey> Keys;
        QMap<QString, SRegistryDeletion> Deletions;
    };

    bool IsSafeDirectory(const QString& path);
    bool IsSafeFile(const QString& path);

    QString Fold(const QString& text)
    {
        return text.toCaseFolded();
    }

    QString FromUtf16(const quint16* data, int length)
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return QString::fromUtf16(
            reinterpret_cast<const char16_t*>(data), length);
#else
        return QString::fromUtf16(data, length);
#endif
    }

    QString DisplayRegistryPath(QString path)
    {
        if (path.isEmpty())
            return QObject::tr("(Hive Root)");
        path.replace('/', '\\');
        if (path.startsWith("\\REGISTRY\\", Qt::CaseInsensitive))
            path.remove(0, 10);
        while (path.startsWith('\\'))
            path.remove(0, 1);

        if (path.compare("MACHINE", Qt::CaseInsensitive) == 0)
            return "HKLM";
        if (path.startsWith("MACHINE\\", Qt::CaseInsensitive))
            return "HKLM\\" + path.mid(8);
        if (path.compare("USER\\CURRENT", Qt::CaseInsensitive) == 0)
            return "HKCU";
        if (path.startsWith("USER\\CURRENT\\", Qt::CaseInsensitive))
            return "HKCU\\" + path.mid(13);
        if (path.compare("USER", Qt::CaseInsensitive) == 0)
            return "HKU";
        if (path.startsWith("USER\\", Qt::CaseInsensitive))
            return "HKU\\" + path.mid(5);
        return path;
    }

    QString CanonicalRegistryPath(QString path)
    {
        QString sid = theAPI ? theAPI->GetCurrentUserSid() : QString();
        QString prefix = QStringLiteral("HKU\\") + sid;
        if (!sid.isEmpty() && (path.compare(prefix, Qt::CaseInsensitive) == 0 ||
                path.startsWith(prefix + QLatin1Char('\\'),
                    Qt::CaseInsensitive))) {
            path.replace(0, prefix.length(), QStringLiteral("HKCU"));
        }
        return Fold(path);
    }

    QString ExpandRegistryRoot(QString path)
    {
        if (path.compare(QStringLiteral("HKCU"), Qt::CaseInsensitive) == 0)
            return QStringLiteral("HKEY_CURRENT_USER");
        if (path.startsWith(QStringLiteral("HKCU\\"), Qt::CaseInsensitive))
            return QStringLiteral("HKEY_CURRENT_USER\\") + path.mid(5);
        if (path.compare(QStringLiteral("HKLM"), Qt::CaseInsensitive) == 0)
            return QStringLiteral("HKEY_LOCAL_MACHINE");
        if (path.startsWith(QStringLiteral("HKLM\\"), Qt::CaseInsensitive))
            return QStringLiteral("HKEY_LOCAL_MACHINE\\") + path.mid(5);
        if (path.compare(QStringLiteral("HKU"), Qt::CaseInsensitive) == 0)
            return QStringLiteral("HKEY_USERS");
        if (path.startsWith(QStringLiteral("HKU\\"), Qt::CaseInsensitive))
            return QStringLiteral("HKEY_USERS\\") + path.mid(4);
        return QString();
    }

    void AddDeletion(SRegistryState& state, const QString& kind,
        const QString& path, const QString& value = QString())
    {
        QString foldedPath = Fold(path);
        QString id = kind + ":" + QString::number(foldedPath.size()) +
            ":" + foldedPath;
        if (kind == "V")
            id += Fold(value);

        SRegistryDeletion deletion;
        deletion.Kind = kind;
        deletion.Path = path;
        deletion.Value = value;
        state.Deletions.insert(id, deletion);
    }

    bool HasDeletedKey(const QSet<QString>& deletedKeys, QString path,
        bool includeSelf)
    {
        if (!includeSelf) {
            int separator = path.lastIndexOf('\\');
            path = separator >= 0 ? path.left(separator) : QString();
        }
        while (!path.isEmpty()) {
            if (deletedKeys.contains(path))
                return true;
            int separator = path.lastIndexOf('\\');
            if (separator < 0)
                break;
            path.truncate(separator);
        }
        return false;
    }

    void NormalizeDeletions(SRegistryState& state)
    {
        QSet<QString> deletedKeys;
        for (auto it = state.Deletions.cbegin();
                it != state.Deletions.cend(); ++it) {
            if (it.value().Kind == "K")
                deletedKeys.insert(Fold(it.value().Path));
        }

        auto it = state.Deletions.begin();
        while (it != state.Deletions.end()) {
            const SRegistryDeletion& deletion = it.value();
            bool covered = deletion.Kind == "K"
                ? HasDeletedKey(deletedKeys, Fold(deletion.Path), false)
                : HasDeletedKey(deletedKeys, Fold(deletion.Path), true);
            if (covered)
                it = state.Deletions.erase(it);
            else
                ++it;
        }
    }

    QDateTime FileTimeToDateTime(quint64 value)
    {
        const quint64 epoch = 116444736000000000ULL;
        if (value < epoch || value == DeleteKeyTime)
            return QDateTime();
        return QDateTime::fromMSecsSinceEpoch(
            qint64((value - epoch) / 10000), Qt::UTC).toLocalTime();
    }

    QString FormatFileTime(quint64 value)
    {
        QDateTime time = FileTimeToDateTime(value);
        return time.isValid() ? time.toString(Qt::ISODateWithMs) : QString();
    }

    QString FormatValue(const SRegistryValue& value)
    {
        if (value.Type == REG_SZ || value.Type == REG_EXPAND_SZ) {
            int length = value.Data.size() / int(sizeof(wchar_t));
            int displayLength = qMin(length, 4096);
            QString text = FromUtf16(
                reinterpret_cast<const quint16*>(value.Data.constData()),
                displayLength);
            while (text.endsWith(QChar('\0')))
                text.chop(1);
            if (displayLength < length)
                text += QObject::tr(" ... (%1 bytes)").arg(value.Data.size());
            return text;
        }
        if (value.Type == REG_MULTI_SZ) {
            int length = value.Data.size() / int(sizeof(wchar_t));
            int displayLength = qMin(length, 4096);
            QString text = FromUtf16(
                reinterpret_cast<const quint16*>(value.Data.constData()),
                displayLength);
            text = text.split(QChar('\0'), Qt::SkipEmptyParts).join("; ");
            if (displayLength < length)
                text += QObject::tr(" ... (%1 bytes)").arg(value.Data.size());
            return text;
        }
        if (value.Type == REG_DWORD && value.Data.size() >= 4) {
            quint32 number = 0;
            memcpy(&number, value.Data.constData(), sizeof(number));
            return QString("0x%1 (%2)").arg(number, 8, 16, QChar('0'))
                .arg(number);
        }
        if (value.Type == REG_QWORD && value.Data.size() >= 8) {
            quint64 number = 0;
            memcpy(&number, value.Data.constData(), sizeof(number));
            return QString("0x%1 (%2)").arg(number, 16, 16, QChar('0'))
                .arg(number);
        }

        QString text = QString::fromLatin1(value.Data.left(128).toHex(' '));
        if (value.Data.size() > 128)
            text += QObject::tr(" ... (%1 bytes)").arg(value.Data.size());
        return text;
    }

    QString ValueTypeName(DWORD type)
    {
        switch (type) {
        case REG_NONE: return "REG_NONE";
        case REG_SZ: return "REG_SZ";
        case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
        case REG_BINARY: return "REG_BINARY";
        case REG_DWORD: return "REG_DWORD";
        case REG_DWORD_BIG_ENDIAN: return "REG_DWORD_BIG_ENDIAN";
        case REG_LINK: return "REG_LINK";
        case REG_MULTI_SZ: return "REG_MULTI_SZ";
        case REG_RESOURCE_LIST: return "REG_RESOURCE_LIST";
        case REG_FULL_RESOURCE_DESCRIPTOR: return "REG_FULL_RESOURCE_DESCRIPTOR";
        case REG_RESOURCE_REQUIREMENTS_LIST: return "REG_RESOURCE_REQUIREMENTS_LIST";
        case REG_QWORD: return "REG_QWORD";
        default: return QString("0x%1").arg(type, 8, 16, QChar('0'));
        }
    }

    bool ReadRegistryKey(HKEY key, const QString& path, SRegistryState& state,
        QString& error, int depth, quint64& entryCount, quint64& dataSize)
    {
        if (depth > 512) {
            error = QObject::tr("Registry nesting is too deep.");
            return false;
        }
        if (++entryCount > quint64(MaxCompareEntries)) {
            error = QObject::tr("The registry generation contains too many entries.");
            return false;
        }

        DWORD subKeyCount = 0;
        DWORD maxSubKeyLength = 0;
        DWORD valueCount = 0;
        DWORD maxValueNameLength = 0;
        DWORD maxValueLength = 0;
        FILETIME lastWrite = {};
        LSTATUS status = RegQueryInfoKeyW(key, NULL, NULL, NULL,
            &subKeyCount, &maxSubKeyLength, NULL, &valueCount,
            &maxValueNameLength, &maxValueLength, NULL, &lastWrite);
        if (status != ERROR_SUCCESS) {
            error = QObject::tr("Could not query registry key %1: %2")
                .arg(DisplayRegistryPath(path)).arg(status);
            return false;
        }

        quint64 writeTime = (quint64(lastWrite.dwHighDateTime) << 32) |
            lastWrite.dwLowDateTime;
        QString displayPath = DisplayRegistryPath(path);
        QString keyId = Fold(displayPath);
        SRegistryKey& current = state.Keys[keyId];
        current.Path = displayPath;
        current.LastWrite = writeTime;
        if (writeTime == DeleteKeyTime)
            AddDeletion(state, "K", displayPath);

        if (maxValueLength > 64 * 1024 * 1024) {
            error = QObject::tr("Registry value data is too large in %1.")
                .arg(displayPath);
            return false;
        }

        QVector<wchar_t> valueName(int(maxValueNameLength) + 2);
        QByteArray valueData(int(maxValueLength), '\0');
        for (DWORD index = 0; index < valueCount; ++index) {
            DWORD nameLength = DWORD(valueName.size() - 1);
            DWORD dataLength = DWORD(valueData.size());
            DWORD type = REG_NONE;
            status = RegEnumValueW(key, index, valueName.data(), &nameLength,
                NULL, &type, reinterpret_cast<BYTE*>(valueData.data()),
                &dataLength);
            if (status != ERROR_SUCCESS) {
                error = QObject::tr("Could not enumerate values in %1: %2")
                    .arg(displayPath).arg(status);
                return false;
            }

            QString name = QString::fromWCharArray(valueName.data(), int(nameLength));
            if (++entryCount > quint64(MaxCompareEntries)) {
                error = QObject::tr(
                    "The registry generation contains too many entries.");
                return false;
            }
            if (type == DeleteValueType) {
                AddDeletion(state, "V", displayPath, name);
                continue;
            }

            if (dataSize > MaxCompareData - dataLength) {
                error = QObject::tr(
                    "The registry generation is too large to compare safely.");
                return false;
            }
            dataSize += dataLength;

            SRegistryValue value;
            value.Name = name;
            value.Type = type;
            value.Data = QByteArray(valueData.constData(), int(dataLength));
            current.Values.insert(Fold(name), value);
        }

        QVector<wchar_t> subKeyName(int(maxSubKeyLength) + 2);
        for (DWORD index = 0; index < subKeyCount; ++index) {
            DWORD nameLength = DWORD(subKeyName.size() - 1);
            FILETIME childWrite = {};
            status = RegEnumKeyExW(key, index, subKeyName.data(), &nameLength,
                NULL, NULL, NULL, &childWrite);
            if (status != ERROR_SUCCESS) {
                error = QObject::tr("Could not enumerate subkeys in %1: %2")
                    .arg(displayPath).arg(status);
                return false;
            }

            HKEY child = NULL;
            status = RegOpenKeyExW(key, subKeyName.data(),
                REG_OPTION_OPEN_LINK, KEY_READ, &child);
            if (status != ERROR_SUCCESS) {
                error = QObject::tr("Could not open a subkey in %1: %2")
                    .arg(displayPath).arg(status);
                return false;
            }

            QString childPath = path;
            if (!childPath.isEmpty())
                childPath += '\\';
            childPath += QString::fromWCharArray(subKeyName.data(), int(nameLength));
            bool ok = ReadRegistryKey(child, childPath, state, error,
                depth + 1, entryCount, dataSize);
            RegCloseKey(child);
            if (!ok)
                return false;
        }
        return true;
    }

    bool ReadUtf16File(const QString& path, QString& text, QString& error,
        bool allowTrailingByte = false)
    {
        QFile file(path);
        DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(path.utf16()));
        DWORD attributeError = GetLastError();
        if (attributes == INVALID_FILE_ATTRIBUTES &&
                (attributeError == ERROR_FILE_NOT_FOUND ||
                 attributeError == ERROR_PATH_NOT_FOUND))
            return true;
        if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & (FILE_ATTRIBUTE_DIRECTORY |
                    FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            error = QObject::tr("Registry history metadata is not a regular file: %1")
                .arg(path);
            return false;
        }
        if (file.size() > qint64(MaxCompareData)) {
            error = QObject::tr("Registry history metadata is too large: %1")
                .arg(path);
            return false;
        }
        if (!file.open(QFile::ReadOnly)) {
            error = QObject::tr("Could not open registry history metadata: %1")
                .arg(path);
            return false;
        }
        QByteArray data = file.readAll();
        if (file.error() != QFile::NoError ||
                ((data.size() & 1) != 0 && !allowTrailingByte)) {
            error = QObject::tr("Could not read registry history metadata: %1")
                .arg(path);
            return false;
        }
        if ((data.size() & 1) != 0)
            data.chop(1);
        if (data.isEmpty())
            return true;
        const quint16* utf16 = reinterpret_cast<const quint16*>(
            data.constData());
        int length = data.size() / int(sizeof(quint16));
        if (length > 0 && utf16[0] == 0xFEFF) {
            ++utf16;
            --length;
        }
        text = FromUtf16(utf16, length);
        return true;
    }

    bool ReadGenerationDeleteMode(const QString& generationPath,
        int& deleteMode, QString& error)
    {
        QString contents;
        if (!ReadUtf16File(generationPath + "\\Generation.ini",
                contents, error))
            return false;
        int version = 0;
        int mode = 0;
        for (QString line : contents.split('\n')) {
            if (line.endsWith('\r'))
                line.chop(1);
            bool ok = false;
            if (line.startsWith("Version="))
                version = line.mid(8).toInt(&ok);
            else if (line.startsWith("DeleteMode="))
                mode = line.mid(11).toInt(&ok);
            if (!ok && (line.startsWith("Version=") ||
                    line.startsWith("DeleteMode=")))
                break;
        }
        if (version == 1 && mode >= 1 && mode <= 3) {
            deleteMode = mode;
            return true;
        }
        error = QObject::tr("The selected generation metadata is invalid.");
        return false;
    }

    int FindUnescapedPipe(const QString& line, int start = 0)
    {
        for (int index = start; index < line.length(); ++index) {
            if (line.at(index) == QLatin1Char('\\') &&
                    index + 1 < line.length()) {
                ++index;
                continue;
            }
            if (line.at(index) == QLatin1Char('|'))
                return index;
        }
        return -1;
    }

    QString UnescapeDeleteField(const QString& field)
    {
        QString result;
        result.reserve(field.length());
        for (int index = 0; index < field.length(); ++index) {
            QChar ch = field.at(index);
            if (ch != QLatin1Char('\\') || index + 1 >= field.length()) {
                result += ch;
                continue;
            }
            QChar escaped = field.at(++index);
            if (escaped == QLatin1Char('|') || escaped == QLatin1Char('\\'))
                result += escaped;
            else if (escaped == QLatin1Char('r'))
                result += QChar('\r');
            else if (escaped == QLatin1Char('n'))
                result += QChar('\n');
            else {
                result += QChar('\\');
                result += escaped;
            }
        }
        return result;
    }

    bool ReadDeleteMetadataFile(const QString& path, bool version3,
        bool journal, SRegistryState& state, QString& error)
    {
        QString contents;
        if (!ReadUtf16File(path, contents, error, journal))
            return false;
        if (!contents.isEmpty() && !contents.endsWith('\n')) {
            if (!journal) {
                error = QObject::tr(
                    "Registry deletion metadata has an incomplete final line: %1")
                    .arg(path);
                return false;
            }
            int lastNewLine = contents.lastIndexOf('\n');
            contents = lastNewLine >= 0
                ? contents.left(lastNewLine + 1) : QString();
        }
        const QStringList lines = contents.split('\n');
        for (QString line : lines) {
            if (line.endsWith('\r'))
                line.chop(1);
            if (line.isEmpty())
                continue;

            if (!version3) {
                QStringList parts = line.split('|');
                bool ok = false;
                int flags = parts.value(1).toInt(&ok, 16);
                if (!ok)
                    continue;
                QString pathName = DisplayRegistryPath(parts.value(0));
                if ((flags & 1) != 0) {
                    int marker = pathName.lastIndexOf("\\$");
                    if (marker >= 0)
                        AddDeletion(state, "V", pathName.left(marker),
                            pathName.mid(marker + 2));
                    else
                        AddDeletion(state, "K", pathName);
                }
                if (state.Deletions.size() > MaxCompareEntries) {
                    error = QObject::tr(
                        "The registry deletion metadata contains too many entries.");
                    return false;
                }
                continue;
            }

            int first = FindUnescapedPipe(line);
            if (first < 0)
                continue;
            int second = FindUnescapedPipe(line, first + 1);
            QString operation = second < 0
                ? line.mid(first + 1)
                : line.mid(first + 1, second - first - 1);
            QString firstPath = DisplayRegistryPath(
                UnescapeDeleteField(line.left(first)));
            if (operation == "1")
                AddDeletion(state, "K", firstPath);
            else if (operation == "3" && second >= 0)
                AddDeletion(state, "V", firstPath,
                    UnescapeDeleteField(line.mid(second + 1)));
            if (state.Deletions.size() > MaxCompareEntries) {
                error = QObject::tr(
                    "The registry deletion metadata contains too many entries.");
                return false;
            }
        }
        return true;
    }

    bool ReadRegistryState(const QString& generationPath,
        SRegistryState& state, QString& error)
    {
        QString hivePath = generationPath + "\\RegHive.hiv";
        if (!IsSafeDirectory(generationPath) || !IsSafeFile(hivePath) ||
                !IsSafeFile(generationPath + "\\Generation.ini")) {
            error = QObject::tr(
                "The selected generation is incomplete or is not a regular directory.");
            return false;
        }

        int deleteMode = 0;
        if (!ReadGenerationDeleteMode(generationPath, deleteMode, error))
            return false;

        HKEY root = NULL;
        LSTATUS status = RegLoadAppKeyW(
            reinterpret_cast<LPCWSTR>(hivePath.utf16()), &root, KEY_READ, 0, 0);
        if (status != ERROR_SUCCESS) {
            error = QObject::tr("Could not open the saved registry hive: %1")
                .arg(status);
            return false;
        }
        quint64 entryCount = 0;
        quint64 dataSize = 0;
        bool ok = ReadRegistryKey(root, QString(), state, error, 0,
            entryCount, dataSize);
        RegCloseKey(root);
        if (!ok)
            return false;

        bool metadataOk = true;
        if (deleteMode == 2)
            metadataOk = ReadDeleteMetadataFile(
                generationPath + "\\RegPaths.dat",
                false, false, state, error);
        else if (deleteMode == 3)
            metadataOk = ReadDeleteMetadataFile(
                    generationPath + "\\RegPaths_v3.dat",
                    true, false, state, error) &&
                ReadDeleteMetadataFile(
                    generationPath + "\\RegPaths_v3.sbie",
                    true, true, state, error);
        if (metadataOk)
            NormalizeDeletions(state);
        return metadataOk;
    }

    QString GenerationDisplayName(const QString& name)
    {
        QDateTime time = QDateTime::fromString(name, "yyyyMMdd-HHmmss-zzz");
        time.setTimeSpec(Qt::UTC);
        return time.isValid() ? time.toLocalTime().toString(Qt::ISODateWithMs)
                              : name;
    }

    bool IsGenerationName(const QString& name)
    {
        return name.size() == 19 &&
            QDateTime::fromString(name, "yyyyMMdd-HHmmss-zzz").isValid();
    }

    bool IsSafeDirectory(const QString& path)
    {
        DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(path.utf16()));
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    }

    bool IsSafeFile(const QString& path)
    {
        DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(path.utf16()));
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & (FILE_ATTRIBUTE_DIRECTORY |
                FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    }

    QStringList SortedIds(const QSet<QString>& ids)
    {
        QStringList result;
        for (const QString& id : ids)
            result.append(id);
        result.sort(Qt::CaseSensitive);
        return result;
    }

    QString FormatSize(quint64 bytes)
    {
        static const char* units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
        double value = double(bytes);
        int unit = 0;
        while (value >= 1024.0 && unit < 4) {
            value /= 1024.0;
            ++unit;
        }
        return QStringLiteral("%1 %2").arg(value, 0, 'f',
            unit == 0 ? 0 : 1).arg(QString::fromLatin1(units[unit]));
    }

    QString FilterValue(QTreeWidgetItem* item, int scope)
    {
        switch (scope) {
        case eChangeField: return item->text(0);
        case ePathField: return item->text(1);
        case eValueField: return item->text(2);
        case eTypeField: return item->text(3) + QLatin1Char(' ') + item->text(4);
        case eDataField: return item->text(5) + QLatin1Char(' ') + item->text(6);
        case eDateField: return item->text(7) + QLatin1Char(' ') + item->text(8);
        default:
            QStringList values;
            for (int column = 0; column < 9; ++column)
                values.append(item->text(column));
            return values.join(QLatin1Char(' '));
        }
    }

    QStringList VisibleHeaders(QTreeWidget* tree)
    {
        QStringList headers;
        for (int column = 0; column < tree->columnCount(); ++column) {
            if (!tree->isColumnHidden(column))
                headers.append(tree->headerItem()->text(column));
        }
        return headers;
    }

    QStringList VisibleRow(QTreeWidget* tree, QTreeWidgetItem* item)
    {
        QStringList row;
        for (int column = 0; column < tree->columnCount(); ++column) {
            if (!tree->isColumnHidden(column))
                row.append(item->text(column));
        }
        return row;
    }

    bool RemoveGenerationDirectory(const QString& path)
    {
        if (!IsSafeDirectory(path))
            return false;

        static const char* files[] = {
            "RegPaths.dat", "RegPaths_v3.dat", "RegPaths_v3.sbie",
            "Generation.ini", "RegHive.hiv.LOG1", "RegHive.hiv.LOG2",
            "RegHive.hiv"
        };
        for (const char* file : files) {
            QString filePath = QDir(path).filePath(QString::fromLatin1(file));
            if (!QFile::exists(filePath))
                continue;
            if (!IsSafeFile(filePath) || !QFile::remove(filePath))
                return false;
        }
        return QDir().rmdir(path);
    }

    bool RemoveHistoryDirectory(const QString& path)
    {
        if (!IsSafeDirectory(path))
            return false;

        QDir history(path);
        const QStringList directories = history.entryList(
            QDir::Dirs | QDir::Hidden | QDir::System |
                QDir::NoDotAndDotDot,
            QDir::Name);
        for (const QString& directory : directories) {
            if (!RemoveGenerationDirectory(history.filePath(directory)))
                return false;
        }
        if (!history.entryList(
                QDir::AllEntries | QDir::Hidden | QDir::System |
                    QDir::NoDotAndDotDot).isEmpty())
            return false;
        return QDir().rmdir(path);
    }

    void AddChange(QTreeWidget* tree, const QString& change,
        const QString& path, const QString& valueName,
        const QString& oldType, const QString& newType,
        const QString& oldData, const QString& newData,
        EChangeCategory category,
        const QString& oldTime = QString(),
        const QString& newTime = QString())
    {
        QTreeWidgetItem* item = new QTreeWidgetItem(tree);
        item->setText(0, change);
        item->setText(1, path);
        item->setText(2, valueName);
        item->setText(3, oldType);
        item->setText(4, newType);
        item->setText(5, oldData);
        item->setText(6, newData);
        item->setText(7, oldTime);
        item->setText(8, newTime);
        item->setData(0, eCanonicalPath, CanonicalRegistryPath(path));
        item->setData(0, eChangeCategory, category);
    }
}

CRegistryHistoryWindow::CRegistryHistoryWindow(const CSandBoxPtr& pBox,
    QWidget* parent)
    : QDialog(parent), m_pBox(pBox), m_ResultsTruncated(false),
      m_ComparisonComplete(false), m_Loading(false), m_Loaded(false)
{
    Qt::WindowFlags flags = windowFlags();
    flags |= Qt::CustomizeWindowHint | Qt::WindowMinimizeButtonHint |
        Qt::WindowMaximizeButtonHint;
    setWindowFlags(flags);
    setWindowFlag(Qt::WindowStaysOnTopHint, theGUI->IsAlwaysOnTop());
    setWindowTitle(tr("%1 - Registry History").arg(CSandMan::GetBoxDisplayName(pBox)));

    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    m_pFilterScope = new QComboBox(this);
    m_pFilterScope->addItem(tr("All fields"), eAllFields);
    m_pFilterScope->addItem(tr("Change"), eChangeField);
    m_pFilterScope->addItem(tr("Registry Path"), ePathField);
    m_pFilterScope->addItem(tr("Value"), eValueField);
    m_pFilterScope->addItem(tr("Type"), eTypeField);
    m_pFilterScope->addItem(tr("Data"), eDataField);
    m_pFilterScope->addItem(tr("Key Date"), eDateField);
    m_pFinder = new CFinder(this, this, CFinder::eRegExp | CFinder::eCaseSens);
    m_pFinder->SetCloseButtonAtEnd(false);
    QAbstractButton* search = m_pFinder->GetToggleButton();
    search->setText(tr("Search"));
    m_pLoadIndicator = new QLabel(this);
    m_pLoadIndicator->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_pLoadIndicator->setMinimumWidth(
        fontMetrics().horizontalAdvance(
            tr("Refreshing... 000000 / 000000 generations")) + 8);
    m_pLoadIndicator->setText(tr("Loading..."));
    m_pRefreshButton = new QPushButton(
        CSandMan::GetIcon("Refresh"), tr("Refresh"), this);
    m_pRefreshButton->setEnabled(false);
    QToolButton* viewOptions = new QToolButton(this);
    viewOptions->setIcon(CSandMan::GetIcon("List"));
    viewOptions->setText(tr("View Options"));
    viewOptions->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    viewOptions->setCheckable(true);
    viewOptions->setAutoRaise(true);
    toolLayout->addWidget(search);
    toolLayout->addWidget(m_pFilterScope);
    toolLayout->addWidget(m_pFinder);
    toolLayout->addStretch();
    toolLayout->addWidget(m_pLoadIndicator);
    toolLayout->addWidget(m_pRefreshButton);
    toolLayout->addWidget(viewOptions);
    mainLayout->addLayout(toolLayout);

    QHBoxLayout* selectionLayout = new QHBoxLayout();
    m_pOlder = new QComboBox(this);
    m_pNewer = new QComboBox(this);
    m_pCompare = new QPushButton(CSandMan::GetIcon("Search"), tr("Compare"), this);
    m_pCompare->setEnabled(false);
    selectionLayout->addWidget(new QLabel(tr("Older generation:"), this));
    selectionLayout->addWidget(m_pOlder, 1);
    selectionLayout->addWidget(new QLabel(tr("Newer generation:"), this));
    selectionLayout->addWidget(m_pNewer, 1);
    selectionLayout->addWidget(m_pCompare);
    mainLayout->addLayout(selectionLayout);

    m_pHighlightSame = new QCheckBox(
        tr("Highlight matching HKCU / current-user HKU paths"), this);
    m_pHighlightSame->setChecked(theConf->GetBool(
        "RegistryHistoryWindow/HighlightSameUserPaths", true));
    m_pShowColors = new QCheckBox(tr("Color change types"), this);
    m_pShowColors->setChecked(theConf->GetBool(
        "RegistryHistoryWindow/ShowChangeColors", true));
    m_pHideDateOnly = new QCheckBox(
        tr("Hide entries with only key date changes"), this);
    m_pHideDateOnly->setChecked(theConf->GetBool(
        "RegistryHistoryWindow/HideDateOnly", true));
    QWidget* viewOptionsWidget = new QWidget(this);
    QHBoxLayout* viewOptionsLayout = new QHBoxLayout(viewOptionsWidget);
    viewOptionsLayout->setContentsMargins(0, 0, 0, 0);
    viewOptionsLayout->addStretch();
    viewOptionsLayout->addWidget(m_pHighlightSame);
    viewOptionsLayout->addWidget(m_pShowColors);
    viewOptionsLayout->addWidget(m_pHideDateOnly);
    viewOptionsWidget->setVisible(false);
    mainLayout->addWidget(viewOptionsWidget);

    m_pTree = new QTreeWidget(this);
    m_pTree->setColumnCount(9);
    m_pTree->setHeaderLabels(QStringList()
        << tr("Change") << tr("Registry Path") << tr("Value")
        << tr("Old Type") << tr("New Type") << tr("Old Data")
        << tr("New Data") << tr("Old Key Date") << tr("New Key Date"));
    m_pTree->setAlternatingRowColors(theConf->GetBool("Options/AltRowColors", false));
    m_pTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_pTree->setUniformRowHeights(true);
    m_pTree->setSortingEnabled(true);
    m_pTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_pFinder->SetTree(m_pTree);
    mainLayout->addWidget(m_pTree, 1);

    m_pSummary = new QLabel(this);
    m_pSummary->setWordWrap(true);
    mainLayout->addWidget(m_pSummary);

    QHBoxLayout* bottomLayout = new QHBoxLayout();
    m_pStatus = new QLabel(this);
    QPushButton* openFolder = new QPushButton(CSandMan::GetIcon("Folder"), tr("Open History Folder"), this);
    m_pDelete = new QPushButton(CSandMan::GetIcon("Erase"), tr("Delete Newer Generation..."), this);
    m_pDelete->setEnabled(false);
    m_pDeleteAll = new QPushButton(
        CSandMan::GetIcon("Erase"), tr("Delete All Generations..."), this);
    m_pDeleteAll->setEnabled(false);
    QPushButton* configure = new QPushButton(
        CSandMan::GetIcon("Settings"), tr("Configure..."), this);
    QPushButton* close = new QPushButton(tr("Close"), this);
    bottomLayout->addWidget(m_pStatus, 1);
    bottomLayout->addWidget(m_pDelete);
    bottomLayout->addWidget(m_pDeleteAll);
    bottomLayout->addWidget(openFolder);
    bottomLayout->addWidget(configure);
    bottomLayout->addWidget(close);
    mainLayout->addLayout(bottomLayout);

    connect(m_pRefreshButton, SIGNAL(clicked(bool)), this, SLOT(Reload()));
    connect(viewOptions, &QToolButton::toggled,
        this, [viewOptionsWidget](bool expanded) {
            viewOptionsWidget->setVisible(expanded);
        });
    connect(search, SIGNAL(toggled(bool)),
        m_pFilterScope, SLOT(setVisible(bool)));
    connect(m_pFilterScope, SIGNAL(currentIndexChanged(int)),
        this, SLOT(UpdateFilterScope()));
    connect(m_pHighlightSame, SIGNAL(toggled(bool)),
        this, SLOT(UpdateSelection()));
    connect(m_pShowColors, &QCheckBox::toggled,
        this, [this](bool) { ApplyViewOptions(); });
    connect(m_pHideDateOnly, &QCheckBox::toggled,
        this, [this](bool) { ApplyFilter(); });
    connect(m_pTree, SIGNAL(itemSelectionChanged()),
        this, SLOT(UpdateSelection()));
    connect(m_pTree, SIGNAL(customContextMenuRequested(const QPoint&)),
        this, SLOT(ShowContextMenu(const QPoint&)));
    connect(m_pCompare, SIGNAL(clicked(bool)), this, SLOT(Compare()));
    connect(configure, SIGNAL(clicked(bool)), this, SLOT(Configure()));
    connect(openFolder, SIGNAL(clicked(bool)), this, SLOT(OpenHistoryFolder()));
    connect(m_pDelete, SIGNAL(clicked(bool)), this, SLOT(DeleteGeneration()));
    connect(m_pDeleteAll, SIGNAL(clicked(bool)),
        this, SLOT(DeleteAllGenerations()));
    connect(close, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect(m_pOlder, SIGNAL(currentIndexChanged(int)), this, SLOT(UpdateControls()));
    connect(m_pNewer, SIGNAL(currentIndexChanged(int)), this, SLOT(UpdateControls()));

    m_pCopyCell = new QAction(CPanelView::m_CopyCell, this);
    m_pCopyRow = new QAction(CPanelView::m_CopyRow, this);
    m_pCopyPanel = new QAction(CPanelView::m_CopyPanel, this);
    m_pCopyRow->setShortcut(QKeySequence::Copy);
    m_pCopyRow->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    addAction(m_pCopyRow);
    connect(m_pCopyCell, SIGNAL(triggered(bool)), this, SLOT(CopyCell()));
    connect(m_pCopyRow, SIGNAL(triggered(bool)), this, SLOT(CopyRow()));
    connect(m_pCopyPanel, SIGNAL(triggered(bool)), this, SLOT(CopyPanel()));

    QAction* resizeColumns = new QAction(
        tr("Resize All Columns to Contents"), this);
    resizeColumns->setShortcut(
        QKeySequence(QStringLiteral("Ctrl+Shift++")));
    resizeColumns->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    addAction(resizeColumns);
    connect(resizeColumns, SIGNAL(triggered(bool)),
        this, SLOT(ResizeColumns()));

    QByteArray geometry = theConf->GetBlob("RegistryHistoryWindow/Window_Geometry");
    if (geometry.isEmpty())
        resize(1300, 650);
    else
        restoreGeometry(geometry);
    if (!m_pTree->header()->restoreState(theConf->GetBlob(
            "RegistryHistoryWindow/Tree_Columns"))) {
        m_pTree->setColumnWidth(0, 120);
        m_pTree->setColumnWidth(1, 360);
        m_pTree->setColumnWidth(2, 180);
        m_pTree->setColumnWidth(5, 220);
        m_pTree->setColumnWidth(6, 220);
    }
    m_pFinder->Open();
    QTimer::singleShot(100, this, SLOT(Reload()));
}

CRegistryHistoryWindow::~CRegistryHistoryWindow()
{
    theConf->SetBlob("RegistryHistoryWindow/Window_Geometry", saveGeometry());
    theConf->SetBlob("RegistryHistoryWindow/Tree_Columns",
        m_pTree->header()->saveState());
    theConf->SetValue("RegistryHistoryWindow/HighlightSameUserPaths",
        m_pHighlightSame->isChecked());
    theConf->SetValue("RegistryHistoryWindow/ShowChangeColors",
        m_pShowColors->isChecked());
    theConf->SetValue("RegistryHistoryWindow/HideDateOnly",
        m_pHideDateOnly->isChecked());
}

void CRegistryHistoryWindow::closeEvent(QCloseEvent* event)
{
    Q_UNUSED(event);
    emit Closed();
    deleteLater();
}

void CRegistryHistoryWindow::Reload()
{
    if (m_Loading)
        return;

    m_Loading = true;
    m_pRefreshButton->setEnabled(false);
    QString loadPrefix = m_Loaded ? tr("Refreshing...") : tr("Loading...");
    m_pLoadIndicator->setText(loadPrefix);
    m_pLoadIndicator->repaint();
    m_pRefreshButton->repaint();

    QString oldName = m_pOlder->currentData().toString();
    QString newName = m_pNewer->currentData().toString();
    m_pOlder->clear();
    m_pNewer->clear();
    m_pTree->clear();
    m_ResultsTruncated = false;
    m_ComparisonComplete = false;

    QString historyPath = m_pBox->GetFileRoot() + "\\RegistryHistory";
    QDir history(historyPath);
    QStringList generations;
    if (IsSafeDirectory(historyPath))
        generations = history.entryList(
            QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (int index = generations.count() - 1; index >= 0; --index) {
        QString generationPath = history.filePath(generations.at(index));
        if (!IsGenerationName(generations.at(index)) ||
                !IsSafeDirectory(generationPath) ||
                !IsSafeFile(generationPath + "/RegHive.hiv") ||
                !IsSafeFile(generationPath + "/Generation.ini"))
            generations.removeAt(index);
    }
    quint64 usedSize = 0;
    for (int index = 0; index < generations.count(); ++index) {
        const QString& generation = generations.at(index);
        if (index == 0 || index + 1 == generations.count() ||
                ((index + 1) % 16) == 0) {
            m_pLoadIndicator->setText(tr("%1 %2 / %3 generations")
                .arg(loadPrefix).arg(index + 1).arg(generations.count()));
            m_pLoadIndicator->repaint();
        }
        QDir generationDir(history.filePath(generation));
        const QFileInfoList files = generationDir.entryInfoList(
            QDir::Files | QDir::Hidden | QDir::NoSymLinks);
        for (const QFileInfo& file : files) {
            if (IsSafeFile(file.absoluteFilePath()))
                usedSize += quint64(file.size());
        }
        QString display = GenerationDisplayName(generation);
        m_pOlder->addItem(display, generation);
        m_pNewer->addItem(display, generation);
    }

    bool autoCompare = m_pBox->GetBool(
        "RegistryHistoryAutoCompare", true);
    int oldIndex = m_pOlder->findData(oldName);
    int newIndex = m_pNewer->findData(newName);
    if (autoCompare && generations.size() >= 2) {
        m_pOlder->setCurrentIndex(generations.size() - 2);
        m_pNewer->setCurrentIndex(generations.size() - 1);
    }
    else {
        if (oldIndex >= 0)
            m_pOlder->setCurrentIndex(oldIndex);
        else if (generations.size() >= 2)
            m_pOlder->setCurrentIndex(generations.size() - 2);
        if (newIndex >= 0)
            m_pNewer->setCurrentIndex(newIndex);
        else if (!generations.isEmpty())
            m_pNewer->setCurrentIndex(generations.size() - 1);
    }

    bool enabled = m_pBox->GetBool("RegistryHistory", false);
    int limit = m_pBox->GetNum("RegistryHistoryMaxGenerations", 20);
    int sizeLimit = m_pBox->GetNum("RegistryHistoryMaxSizeKB", 1024 * 1024);
    QString generationLimit = limit == 0
        ? tr("unlimited") : QString::number(limit);
    QString byteLimit = sizeLimit == 0
        ? tr("unlimited") : FormatSize(quint64(sizeLimit) * 1024);
    m_pSummary->setText(tr("Usage / limits: %1 / %2 generation(s); %3 / %4. "
        "When a limit is exceeded, the oldest completed generations are removed "
        "automatically and the newest generation is kept. Comparisons show only "
        "the sandbox registry layer.%5")
        .arg(generations.size()).arg(generationLimit)
        .arg(FormatSize(usedSize)).arg(byteLimit)
        .arg(enabled ? QString() : tr(" Registry history capture is disabled.")));
    m_pStatus->setText(tr("Listed: 0 change(s); %1 generation(s)")
        .arg(generations.size()));
    UpdateControls();
    m_pLoadIndicator->clear();
    m_pRefreshButton->setEnabled(true);
    m_Loading = false;
    m_Loaded = true;
    if (autoCompare && generations.size() >= 2)
        QTimer::singleShot(0, this, SLOT(Compare()));
}

void CRegistryHistoryWindow::UpdateControls()
{
    bool valid = m_pOlder->currentIndex() >= 0 &&
        m_pNewer->currentIndex() >= 0 &&
        m_pOlder->currentData() != m_pNewer->currentData();
    m_pCompare->setEnabled(valid);
    m_pDelete->setEnabled(m_pNewer->currentIndex() >= 0);
    m_pDeleteAll->setEnabled(IsSafeDirectory(
        m_pBox->GetFileRoot() + "\\RegistryHistory"));
}

void CRegistryHistoryWindow::ResizeColumns()
{
    for (int column = 0; column < m_pTree->columnCount(); ++column)
        m_pTree->resizeColumnToContents(column);
}

void CRegistryHistoryWindow::SetFilter(const QRegularExpression& regExp,
    int options, int column)
{
    Q_UNUSED(options);
    Q_UNUSED(column);
    m_FilterExp = regExp;
    ApplyFilter();
}

void CRegistryHistoryWindow::UpdateFilterScope()
{
    ApplyFilter();
}

void CRegistryHistoryWindow::ApplyFilter()
{
    int scope = m_pFilterScope->currentData().toInt();
    bool empty = m_FilterExp.pattern().isEmpty();
    bool hideDateOnly = m_pHideDateOnly->isChecked();
    int total = m_pTree->topLevelItemCount();
    if (total == 0 && m_ComparisonComplete) {
        m_pStatus->setText(tr(
            "No registry differences were found between the selected generations."));
        return;
    }
    int listed = 0;
    for (int index = 0; index < total; ++index) {
        QTreeWidgetItem* item = m_pTree->topLevelItem(index);
        bool visible = !hideDateOnly ||
            item->data(0, eChangeCategory).toInt() != eDateOnly;
        visible = visible && (empty ||
            m_FilterExp.match(FilterValue(item, scope)).hasMatch());
        item->setHidden(!visible);
        if (visible)
            ++listed;
    }
    QString status = tr("Listed: %1 of %2 change(s)")
        .arg(listed).arg(total);
    if (m_ResultsTruncated)
        status += tr("; results were truncated");
    m_pStatus->setText(status);
}

void CRegistryHistoryWindow::ApplyViewOptions()
{
    bool colors = m_pShowColors->isChecked();
    for (int index = 0; index < m_pTree->topLevelItemCount(); ++index) {
        QTreeWidgetItem* item = m_pTree->topLevelItem(index);
        QColor color;
        if (colors) {
            switch (item->data(0, eChangeCategory).toInt()) {
            case eAdded:
                color = theGUI->m_DarkTheme
                    ? QColor(110, 220, 135) : QColor(0, 125, 55);
                break;
            case eDeleted:
                color = theGUI->m_DarkTheme
                    ? QColor(255, 125, 125) : QColor(180, 25, 25);
                break;
            case eModified:
                color = theGUI->m_DarkTheme
                    ? QColor(115, 185, 255) : QColor(20, 90, 175);
                break;
            case eDateOnly:
                color = theGUI->m_DarkTheme
                    ? QColor(190, 190, 190) : QColor(100, 100, 100);
                break;
            }
        }
        for (int column = 0; column < m_pTree->columnCount(); ++column)
            item->setForeground(column, colors ? QBrush(color) : QBrush());
    }
    UpdateSelection();
    ApplyFilter();
}

void CRegistryHistoryWindow::UpdateSelection()
{
    QString canonical;
    QTreeWidgetItem* current = m_pTree->currentItem();
    if (m_pHighlightSame->isChecked() && current && current->isSelected())
        canonical = current->data(0, eCanonicalPath).toString();
    QBrush matchBrush(theGUI->m_DarkTheme
        ? QColor(125, 105, 0) : QColor(255, 248, 190));
    for (int index = 0; index < m_pTree->topLevelItemCount(); ++index) {
        QTreeWidgetItem* item = m_pTree->topLevelItem(index);
        bool match = !canonical.isEmpty() && item != current &&
            item->data(0, eCanonicalPath).toString() == canonical;
        for (int column = 0; column < m_pTree->columnCount(); ++column)
            item->setBackground(column, match ? matchBrush : QBrush());
    }
}

void CRegistryHistoryWindow::ShowContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = m_pTree->itemAt(pos);
    if (!item)
        return;
    if (!item->isSelected()) {
        m_pTree->clearSelection();
        item->setSelected(true);
    }
    int column = m_pTree->columnAt(pos.x());
    if (column < 0)
        column = 0;
    m_pTree->setCurrentItem(item, column, QItemSelectionModel::NoUpdate);

    QMenu menu(this);
    bool canOpen = !ExpandRegistryRoot(item->text(1)).isEmpty();
    QMenu* openMenu = menu.addMenu(
        CSandMan::GetIcon("RegEdit"), tr("Open in Registry Editor"));
    QAction* openHost = openMenu->addAction(tr("Host"));
    QAction* openSandbox = openMenu->addAction(
        CSandMan::GetIcon("Run"), tr("Sandbox"));
    openHost->setEnabled(canOpen);
    openHost->setToolTip(tr("Open the selected key in the real host registry."));
    openSandbox->setToolTip(tr("Run Registry Editor inside this sandbox."));
    connect(openHost, SIGNAL(triggered(bool)), this, SLOT(OpenKeyInHost()));
    connect(openSandbox, SIGNAL(triggered(bool)), this, SLOT(OpenKeyInSandbox()));

    menu.addSeparator();
    QAction* useFilter = menu.addAction(tr("Use as Filter"));
    QAction* excludeFilter = menu.addAction(tr("Exclude from View"));
    bool hasFilterValue = false;
    for (QTreeWidgetItem* selected : m_pTree->selectedItems()) {
        if (!selected->text(column).isEmpty()) {
            hasFilterValue = true;
            break;
        }
    }
    useFilter->setEnabled(hasFilterValue);
    excludeFilter->setEnabled(hasFilterValue);
    connect(useFilter, SIGNAL(triggered(bool)), this, SLOT(UseAsFilter()));
    connect(excludeFilter, SIGNAL(triggered(bool)),
        this, SLOT(ExcludeFromView()));
    m_pCopyCell->setEnabled(!item->text(column).isEmpty());
    m_pCopyRow->setEnabled(!m_pTree->selectedItems().isEmpty());
    m_pCopyPanel->setEnabled(m_pTree->topLevelItemCount() != 0);
    menu.addAction(m_pCopyCell);
    menu.addAction(m_pCopyRow);
    menu.addAction(m_pCopyPanel);
    menu.exec(m_pTree->viewport()->mapToGlobal(pos));
}

void CRegistryHistoryWindow::CopyCell()
{
    int column = m_pTree->currentColumn();
    QList<QStringList> rows;
    for (QTreeWidgetItem* item : m_pTree->selectedItems()) {
        if (!item->isHidden())
            rows.append(QStringList() << item->text(column));
    }
    CPanelView::CopyToClipboard(QStringList(), rows);
}

void CRegistryHistoryWindow::CopyRow()
{
    QList<QStringList> rows;
    for (QTreeWidgetItem* item : m_pTree->selectedItems()) {
        if (!item->isHidden())
            rows.append(VisibleRow(m_pTree, item));
    }
    CPanelView::CopyToClipboard(VisibleHeaders(m_pTree), rows);
}

void CRegistryHistoryWindow::CopyPanel()
{
    QList<QStringList> rows;
    for (int index = 0; index < m_pTree->topLevelItemCount(); ++index) {
        QTreeWidgetItem* item = m_pTree->topLevelItem(index);
        if (!item->isHidden())
            rows.append(VisibleRow(m_pTree, item));
    }
    CPanelView::CopyToClipboard(VisibleHeaders(m_pTree), rows);
}

void CRegistryHistoryWindow::UseAsFilter()
{
    ApplySelectionFilter(false);
}

void CRegistryHistoryWindow::ExcludeFromView()
{
    ApplySelectionFilter(true);
}

void CRegistryHistoryWindow::ApplySelectionFilter(bool exclude)
{
    int column = m_pTree->currentColumn();
    int scope = eAllFields;
    switch (column) {
    case 0: scope = eChangeField; break;
    case 1: scope = ePathField; break;
    case 2: scope = eValueField; break;
    case 3:
    case 4: scope = eTypeField; break;
    case 5:
    case 6: scope = eDataField; break;
    case 7:
    case 8: scope = eDateField; break;
    }

    QStringList alternatives;
    int expressionLength = 0;
    for (QTreeWidgetItem* item : m_pTree->selectedItems()) {
        QString value = item->text(column);
        if (!value.isEmpty()) {
            QString escaped = QRegularExpression::escape(value);
            if (!alternatives.contains(escaped)) {
                expressionLength += escaped.length() + 1;
                if (expressionLength > MaxGeneratedFilterLength) {
                    QMessageBox::warning(this, tr("Registry History"), tr(
                        "The selected values are too large to create a safe "
                        "regular-expression filter."));
                    return;
                }
                alternatives.append(escaped);
            }
        }
    }
    if (alternatives.isEmpty())
        return;

    int scopeIndex = m_pFilterScope->findData(scope);
    if (scopeIndex >= 0)
        m_pFilterScope->setCurrentIndex(scopeIndex);
    QString expression = QStringLiteral("(?:%1)")
        .arg(alternatives.join(QLatin1Char('|')));
    if (exclude) {
        expression = QStringLiteral("^(?![\\s\\S]*%1)[\\s\\S]*$")
            .arg(expression);
    }
    m_pFinder->SetSearchText(expression, true);
}

void CRegistryHistoryWindow::OpenKeyInHost()
{
    OpenRegistryKey(false);
}

void CRegistryHistoryWindow::OpenKeyInSandbox()
{
    OpenRegistryKey(true);
}

void CRegistryHistoryWindow::OpenRegistryKey(bool sandbox)
{
    if (sandbox) {
        QList<SB_STATUS> results;
        results.append(m_pBox->RunStart(QStringLiteral("regedit.exe")));
        theGUI->CheckResults(results, this);
        return;
    }

    QTreeWidgetItem* item = m_pTree->currentItem();
    if (!item)
        return;
    QString keyPath = ExpandRegistryRoot(item->text(1));
    if (keyPath.isEmpty())
        return;
    keyPath.prepend(QStringLiteral("Computer\\"));

    if (theConf->GetInt("Options/WarnOpenRegistry", -1) == -1) {
        bool state = false;
        if (CCheckableMessageBox::question(this, "Sandboxie-Plus", tr(
                "WARNING: This opens the real host registry outside the "
                "sandbox. Changes or deletions made in Registry Editor affect "
                "Windows and installed applications directly. Do not modify "
                "anything unless you understand the consequences."),
                tr("Don't show this warning in future"), &state,
                QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                QDialogButtonBox::Ok, QMessageBox::Warning) !=
                QDialogButtonBox::Ok)
            return;
        if (state)
            theConf->SetValue("Options/WarnOpenRegistry", 1);
    }

    ShellOpenRegKey(keyPath);
}

void CRegistryHistoryWindow::Compare()
{
    QString olderName = m_pOlder->currentData().toString();
    QString newerName = m_pNewer->currentData().toString();
    if (olderName.isEmpty() || newerName.isEmpty() || olderName == newerName)
        return;
    if (olderName > newerName)
        qSwap(olderName, newerName);

    QString root = m_pBox->GetFileRoot() + "\\RegistryHistory\\";
    if (!IsSafeDirectory(root.left(root.size() - 1))) {
        QMessageBox::critical(this, tr("Registry History"),
            tr("The registry history folder is unavailable or is not a regular directory."));
        return;
    }
    SRegistryState older;
    SRegistryState newer;
    QString error;
    m_pLoadIndicator->setText(tr("Comparing..."));
    m_pLoadIndicator->repaint();
    m_pRefreshButton->setEnabled(false);
    m_pCompare->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    bool ok = ReadRegistryState(root + olderName, older, error) &&
        ReadRegistryState(root + newerName, newer, error);
    QApplication::restoreOverrideCursor();
    if (!ok) {
        m_pLoadIndicator->clear();
        m_pRefreshButton->setEnabled(true);
        UpdateControls();
        QMessageBox::critical(this, tr("Registry History"), error);
        return;
    }

    m_pTree->setSortingEnabled(false);
    m_pTree->clear();
    m_ResultsTruncated = false;
    m_ComparisonComplete = true;
    QSet<QString> keyIds;
    for (auto it = older.Keys.cbegin(); it != older.Keys.cend(); ++it)
        keyIds.insert(it.key());
    for (auto it = newer.Keys.cbegin(); it != newer.Keys.cend(); ++it)
        keyIds.insert(it.key());
    bool truncated = false;
    for (const QString& keyId : SortedIds(keyIds)) {
        if (m_pTree->topLevelItemCount() >= MaxDisplayedChanges) {
            truncated = true;
            break;
        }
        bool hadKey = older.Keys.contains(keyId);
        bool hasKey = newer.Keys.contains(keyId);
        const SRegistryKey oldKey = older.Keys.value(keyId);
        const SRegistryKey newKey = newer.Keys.value(keyId);
        QString path = hasKey ? newKey.Path : oldKey.Path;
        if (!hadKey || !hasKey) {
            AddChange(m_pTree, hasKey ? tr("Key added") : tr("Key removed"),
                path, QString(), QString(), QString(), QString(), QString(),
                hasKey ? eAdded : eDeleted,
                FormatFileTime(oldKey.LastWrite), FormatFileTime(newKey.LastWrite));
        }

        QSet<QString> valueIds;
        for (auto it = oldKey.Values.cbegin(); it != oldKey.Values.cend(); ++it)
            valueIds.insert(it.key());
        for (auto it = newKey.Values.cbegin(); it != newKey.Values.cend(); ++it)
            valueIds.insert(it.key());
        bool valueChanged = false;
        for (const QString& valueId : SortedIds(valueIds)) {
            if (m_pTree->topLevelItemCount() >= MaxDisplayedChanges) {
                truncated = true;
                break;
            }
            bool hadValue = oldKey.Values.contains(valueId);
            bool hasValue = newKey.Values.contains(valueId);
            const SRegistryValue oldValue = oldKey.Values.value(valueId);
            const SRegistryValue newValue = newKey.Values.value(valueId);
            if (hadValue && hasValue && oldValue.Type == newValue.Type &&
                    oldValue.Data == newValue.Data)
                continue;
            valueChanged = true;
            QString change = !hadValue ? tr("Value added")
                : !hasValue ? tr("Value removed") : tr("Value changed");
            AddChange(m_pTree, change, path,
                (hasValue ? newValue.Name : oldValue.Name).isEmpty()
                    ? tr("(Default)")
                    : (hasValue ? newValue.Name : oldValue.Name),
                hadValue ? ValueTypeName(oldValue.Type) : QString(),
                hasValue ? ValueTypeName(newValue.Type) : QString(),
                hadValue ? FormatValue(oldValue) : QString(),
                hasValue ? FormatValue(newValue) : QString(),
                !hadValue ? eAdded : !hasValue ? eDeleted : eModified,
                FormatFileTime(oldKey.LastWrite), FormatFileTime(newKey.LastWrite));
        }

        if (truncated)
            break;

        if (hadKey && hasKey && !valueChanged && oldKey.LastWrite != newKey.LastWrite) {
            AddChange(m_pTree, tr("Key date changed"), path, QString(),
                QString(), QString(), QString(), QString(),
                eDateOnly,
                FormatFileTime(oldKey.LastWrite), FormatFileTime(newKey.LastWrite));
        }
    }

    QSet<QString> deletionIds;
    for (auto it = older.Deletions.cbegin(); it != older.Deletions.cend(); ++it)
        deletionIds.insert(it.key());
    for (auto it = newer.Deletions.cbegin(); it != newer.Deletions.cend(); ++it)
        deletionIds.insert(it.key());
    for (const QString& deletionId : truncated
            ? QStringList() : SortedIds(deletionIds)) {
        if (m_pTree->topLevelItemCount() >= MaxDisplayedChanges) {
            truncated = true;
            break;
        }
        bool wasDeleted = older.Deletions.contains(deletionId);
        bool isDeleted = newer.Deletions.contains(deletionId);
        if (wasDeleted == isDeleted)
            continue;
        SRegistryDeletion deletion = isDeleted
            ? newer.Deletions.value(deletionId)
            : older.Deletions.value(deletionId);
        AddChange(m_pTree,
            isDeleted ? tr("Deletion marker added") : tr("Deletion marker removed"),
            deletion.Path, deletion.Value, QString(), QString(),
            QString(), QString(), isDeleted ? eDeleted : eAdded);
    }

    m_ResultsTruncated = truncated;
    m_pTree->setSortingEnabled(true);
    m_pTree->sortItems(1, Qt::AscendingOrder);
    ApplyViewOptions();
    m_pLoadIndicator->clear();
    m_pRefreshButton->setEnabled(true);
    UpdateControls();
}

void CRegistryHistoryWindow::Configure()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Registry History Options"));
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    QCheckBox* enabled = new QCheckBox(
        tr("Capture a registry generation after each completed sandbox run"), &dialog);
    enabled->setChecked(m_pBox->GetBool("RegistryHistory", false));
    layout->addWidget(enabled);
    QCheckBox* autoCompare = new QCheckBox(
        tr("Automatically compare the two newest generations after loading"),
        &dialog);
    autoCompare->setChecked(m_pBox->GetBool(
        "RegistryHistoryAutoCompare", true));
    layout->addWidget(autoCompare);

    QFormLayout* form = new QFormLayout();
    QSpinBox* limit = new QSpinBox(&dialog);
    limit->setRange(0, 10000);
    limit->setSpecialValueText(tr("Unlimited"));
    limit->setValue(m_pBox->GetNum("RegistryHistoryMaxGenerations", 20));
    form->addRow(tr("Maximum generations:"), limit);
    QSpinBox* sizeLimit = new QSpinBox(&dialog);
    sizeLimit->setRange(0, 2 * 1024 * 1024);
    sizeLimit->setSpecialValueText(tr("Unlimited"));
    sizeLimit->setSuffix(tr(" KB"));
    sizeLimit->setValue(m_pBox->GetNum("RegistryHistoryMaxSizeKB", 1024 * 1024));
    form->addRow(tr("Maximum total size:"), sizeLimit);
    layout->addLayout(form);

    QLabel* note = new QLabel(tr(
        "Captures occur after the last sandbox process exits. Registry values "
        "do not contain individual modification timestamps."), &dialog);
    note->setWordWrap(true);
    layout->addWidget(note);

    QDialogButtonBox* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, SIGNAL(accepted()), &dialog, SLOT(accept()));
    connect(buttons, SIGNAL(rejected()), &dialog, SLOT(reject()));
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted)
        return;

    QList<SB_STATUS> results;
    auto saveBool = [this, &results](const QString& setting,
            bool value, bool defaultValue) {
        QString newValue = value == defaultValue
            ? QString() : (value ? QStringLiteral("y") : QStringLiteral("n"));
        QString oldValue = m_pBox->GetText(setting).trimmed();
        if (newValue.compare(oldValue, Qt::CaseInsensitive) == 0)
            return;
        results.append(newValue.isEmpty()
            ? m_pBox->DelValue(setting)
            : m_pBox->SetText(setting, newValue));
    };
    auto saveNum = [this, &results](const QString& setting,
            int value, int defaultValue) {
        QString newValue = value == defaultValue
            ? QString() : QString::number(value);
        QString oldValue = m_pBox->GetText(setting).trimmed();
        if (newValue == oldValue)
            return;
        results.append(newValue.isEmpty()
            ? m_pBox->DelValue(setting)
            : m_pBox->SetText(setting, newValue));
    };
    saveBool("RegistryHistory", enabled->isChecked(), false);
    saveBool("RegistryHistoryAutoCompare", autoCompare->isChecked(), true);
    saveNum("RegistryHistoryMaxGenerations", limit->value(), 20);
    saveNum("RegistryHistoryMaxSizeKB", sizeLimit->value(), 1024 * 1024);
    theGUI->CheckResults(results, this);
    Reload();
}

void CRegistryHistoryWindow::OpenHistoryFolder()
{
    QString path = m_pBox->GetFileRoot() + "\\RegistryHistory";
    if (!IsSafeDirectory(path)) {
        QMessageBox::information(this, tr("Registry History"),
            tr("No registry history has been captured yet."));
        return;
    }
    ShellExecuteW(NULL, NULL, reinterpret_cast<LPCWSTR>(path.utf16()),
        NULL, NULL, SW_SHOWNORMAL);
}

bool CRegistryHistoryWindow::CanDeleteHistory()
{
    if (m_pBox->GetBool("NeverDelete", false)) {
        QMessageBox::warning(this, "Sandboxie-Plus",
            tr("Delete protection is enabled for this sandbox."));
        return false;
    }
    if (m_pBox->GetActiveProcessCount() > 0) {
        QMessageBox::warning(this, "Sandboxie-Plus",
            tr("Registry history cannot be deleted while the sandbox is running."));
        return false;
    }
    return true;
}

void CRegistryHistoryWindow::DeleteGeneration()
{
    if (!CanDeleteHistory())
        return;

    QString generation = m_pNewer->currentData().toString();
    if (generation.isEmpty())
        return;
    if (QMessageBox::question(this, tr("Delete Registry Generation"),
            tr("Delete registry generation %1?")
                .arg(GenerationDisplayName(generation))) != QMessageBox::Yes)
        return;

    QString historyPath = m_pBox->GetFileRoot() + "\\RegistryHistory";
    QString path = historyPath + "\\" + generation;
    if (!IsSafeDirectory(historyPath)) {
        QMessageBox::critical(this, tr("Registry History"),
            tr("The registry history folder is unavailable or is not a regular directory."));
        return;
    }
    if (!RemoveGenerationDirectory(path)) {
        QMessageBox::critical(this, tr("Registry History"),
            tr("The registry generation could not be deleted."));
        return;
    }
    Reload();
}

void CRegistryHistoryWindow::DeleteAllGenerations()
{
    if (!CanDeleteHistory())
        return;

    QString historyPath = m_pBox->GetFileRoot() + "\\RegistryHistory";
    if (!IsSafeDirectory(historyPath)) {
        QMessageBox::information(this, tr("Registry History"),
            tr("No registry history has been captured yet."));
        return;
    }
    if (QMessageBox::question(this, tr("Delete Registry History"), tr(
            "Delete all registry generations and remove the RegistryHistory "
            "folder?")) != QMessageBox::Yes)
        return;

    if (!RemoveHistoryDirectory(historyPath)) {
        QMessageBox::critical(this, tr("Registry History"), tr(
            "Registry History could not be removed completely. Some files "
            "or generations may remain."));
        Reload();
        return;
    }
    Reload();
}
