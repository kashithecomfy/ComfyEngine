#pragma once

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QDockWidget>
#include <QColor>
#include <memory>
#include "core/TargetProcess.h"
#include "core/MemoryScanner.h"
#include "core/CodeInjector.h"
#include "gui/PointerScannerDialog.h"
#include "gui/ProcessListModel.h"
#include <vector>
#include <QByteArray>
#include <unordered_map>
#include <unordered_set>

class QProgressBar;
class QThread;
class QListView;
class QPushButton;
class QLabel;
class QLineEdit;
class QComboBox;
class QTableWidget;
class QTableView;
class QTextEdit;
class QCheckBox;
class QTimer;
class QSpinBox;
class QGroupBox;
class QStackedWidget;
class PointerScannerDialog;
class AutoAssemblerDialog;
class ProcessDialog;
class MemoryViewerWindow;
class WatchWindow;
class ValueMonitorDialog;
class QToolBar;
class QSortFilterProxyModel;
class ScanResultsModel;
class QDockWidget;
class QPlainTextEdit;
class QFocusEvent;
class QCloseEvent;
class QAction;
class QListWidget;
class QTreeWidget;
class QWidget;
class QGraphicsView;
class QGraphicsScene;
class QVariant;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    void onDetach();
    void onFirstScan();
    void onNextScan();
    void onUndoScan();
    void onModifyValue();
    void onPatchBytes();
    void onRestorePatch();
    void onAddWatch();
    void onRemoveWatch();
    void onUpdateWatchValue();
    void onViewMemory();
    void onProcessClicked();
    void onSaveTable();
    void onLoadTable();
    void onLaunchTestGame();
    void onTrackValue(uintptr_t address, core::ValueType type, const QString &label = QString());

private:
    void setupUi();
    void updateStatus(const QString &text);
    void setStatusDetail(const QString &text);
    void refreshStatusLabel();
    core::ValueType currentValueType() const;
    core::ScanMode currentScanMode() const;
    core::ScanParams currentScanParams(bool forNext) const;
    void updateInputBoxState();
    void populateResults();
    void populateWatchList(bool force = false);
    void refreshWatchValues(bool force = false);
    void refreshResultValues();
    QString hexDump(uintptr_t address, size_t length) const;
    void updateAttachUi();
    void recordScanSnapshot();
    void resetScanHistory();
    void updateUndoState();
    void setResultDisplayType(core::ValueType type);
    void updateResultColumnVisibility();
    int resultRowCount() const;
    QVariant resultData(int row, int column, int role) const;
    uintptr_t resultAddressForRow(int row) const;
    uintptr_t resolvePointerChain(uintptr_t base, const std::vector<int64_t> &offsets) const;
    void notifyResultsReset();
    void applyGlobalStyle();
    void onScriptSubmitted(const QString &name, const QString &script);
    bool setScriptState(size_t index, bool enable);
    AutoAssemblerDialog *ensureAutoAsmRunner();
    void promptPatchBytes(uintptr_t address);
    void activateModule(const QString &tag);
    void showDock(QDockWidget *dock);
    void pulseWatchRow(int row, const QColor &color);
    double decodeNumeric(const QByteArray &bytes, core::ValueType type, bool *ok) const;
    double decodeRaw(uint64_t raw, core::ValueType type, bool *ok) const;
    void updateTrackedEntries();
    void recordSnapshot();
    void compareSnapshot();
    void updateSmartPanel(uintptr_t address, core::ValueType type, const QString &source);
    void showSpark(uintptr_t address);
    void analyzeMetaResults();
    bool looksLikePointer(uintptr_t value) const;
    const core::MemoryRegion *regionFor(uintptr_t address) const;
    QString metaSummary(uintptr_t address) const;
    void pulseTableRow(QTableWidget *table, int row, const QColor &color, int duration = 220);
    void updatePointerGraph(uintptr_t base, qint64 offset, uintptr_t finalAddr);
    void updatePointerGraph(const std::vector<core::PointerHit> &hits, int highlightIndex);
    void refreshMemoryVisualization();
    void updateResultsCount();
    QString readBytesHex(uintptr_t address, int count) const;
    QString makePatchScript(uintptr_t address, const QString &patchBytes, bool viaAob = false) const;
    void loadSettings();
    void persistSetting(const QString &key, const QVariant &value);

    QLabel *statusLabel_{};
    QString statusBase_;
    QString statusDetail_;

    QLineEdit *valueEdit_{};
    QLineEdit *valueEdit2_{};
    QComboBox *typeCombo_{};
    QComboBox *modeCombo_{};
    QCheckBox *hexCheck_{};
    QLineEdit *alignmentEdit_{};
    QLineEdit *startAddrEdit_{};
    QLineEdit *endAddrEdit_{};
    QCheckBox *writableCheck_{};
    QCheckBox *executableCheck_{};
    QCheckBox *skipMaskedCheck_{};
    QCheckBox *fastScanCheck_{};
    QPushButton *firstScanBtn_{};
    QPushButton *nextScanBtn_{};
    QPushButton *undoScanBtn_{};
    QProgressBar *scanProgress_{};
    QTableView *resultsTable_{};
    ScanResultsModel *resultsModel_{};
    QSortFilterProxyModel *resultsProxy_{};
    QLabel *resultsCountLabel_{};
    QLineEdit *newValueEdit_{};
    QPushButton *modifyBtn_{};
    QCheckBox *freezeCheck_{};
    QPushButton *unfreezeBtn_{};

    QLineEdit *patchAddressEdit_{};
    QLineEdit *patchBytesEdit_{};
    QPushButton *patchBtn_{};
    QPushButton *restoreBtn_{};

    QTableWidget *watchTable_{};
    QPushButton *addWatchBtn_{};
    QPushButton *removeWatchBtn_{};
    QPushButton *updateWatchBtn_{};
    QLineEdit *watchValueEdit_{};
    QPushButton *saveTableBtn_{};
    QPushButton *loadTableBtn_{};
    QPushButton *refreshValuesBtn_{};
    QPushButton *stopScanBtn_{};
    QCheckBox *autoRefreshCheck_{};
    QSpinBox *refreshIntervalSpin_{};
    QToolBar *mainToolbar_{};
    QAction *attachAction_{};
    QAction *snapshotAction_{};
    QAction *compareSnapshotAction_{};
    QTimer *scanProgressTimer_{};

    ProcessListModel *processModel_{};
    std::unique_ptr<core::TargetProcess> target_;
    std::unique_ptr<core::MemoryScanner> scanner_;
    std::unique_ptr<core::CodeInjector> injector_;

    QTimer *freezeTimer_{};
    QTimer *watchRefreshTimer_{};

    struct WatchEntry {
        uintptr_t address;
        core::ValueType type;
        QString description;
        bool isPointer{false};
        std::vector<int64_t> offsets; // For [base]+off1]+off2...
        bool frozen{false};
        QByteArray stored; // value to enforce when frozen
        QByteArray last;   // last observed value
        QByteArray prev;   // previous observed value
        bool isScript{false};
        bool scriptActive{false};
        QString scriptSource;
    };
    std::vector<WatchEntry> watches_;
    std::unordered_map<uintptr_t, uint64_t> lastValues_;
    std::unordered_map<uintptr_t, uint64_t> firstValues_;
    std::unordered_map<uintptr_t, uint64_t> liveValues_;
    std::unordered_set<uintptr_t> changedAddresses_;
    std::unordered_set<uintptr_t> spikedAddresses_;
    std::unordered_map<uintptr_t, qint64> sparkTimes_;
    std::vector<std::vector<core::ScanResult>> scanHistory_;
    core::ValueType resultDisplayType_{core::ValueType::Int32};
    bool showPreviousColumn_{true};
    PointerScannerDialog *pointerScanner_{};
    AutoAssemblerDialog *autoAsm_{};
    AutoAssemblerDialog *autoAsmRunner_{};
    ProcessDialog *processDialog_{};
    MemoryViewerWindow *memoryViewer_{};
    QDockWidget *memoryViewerDock_{};
    QDockWidget *notesDock_{};
    QDockWidget *scriptDock_{};
    QDockWidget *scanDock_{};
    QDockWidget *resultsDock_{};
    QDockWidget *watchDock_{};
    QDockWidget *patchDock_{};
    QDockWidget *sidebarDock_{};
    QDockWidget *trackingDock_{};
    QDockWidget *smartDock_{};
    QDockWidget *pointerDock_{};
    QDockWidget *memoryVizDock_{};
    QDockWidget *settingsDock_{};
    QDockWidget *aboutDock_{};
    QPlainTextEdit *notesEdit_{};
    QPlainTextEdit *scriptEditor_{};
    QPushButton *scriptSendBtn_{};
    QLineEdit *scriptNameEdit_{};
    QListWidget *sidebarList_{};
    QTreeWidget *trackingList_{};
    QPlainTextEdit *smartPanel_{};
    QWidget *centralSpacer_{};
    QGraphicsView *pointerGraphView_{};
    QGraphicsScene *pointerScene_{};
    QGraphicsView *memoryVizView_{};
    QGraphicsScene *memoryScene_{};
    QThread *scanThread_{};
    bool scanInProgress_{false};
    bool watchValueEditing_{false};
    uintptr_t globalAddress_{0};
    std::vector<core::MemoryRegion> cachedRegions_;
    std::unordered_set<uintptr_t> trackedAddresses_;
    std::unordered_map<uintptr_t, core::ValueType> trackedTypes_;
    std::unordered_map<uintptr_t, uint64_t> snapshotValues_;
    bool hasSnapshot_{false};
    qint64 sparkWindowMs_{420};
    QTimer *sparkTimer_{};
    std::unordered_map<uintptr_t, double> metaScores_;
    std::unordered_map<uintptr_t, core::ValueType> guessedTypes_;
    std::unordered_map<uintptr_t, QString> metaGroups_;
    std::unordered_set<uintptr_t> pointerCandidates_;
    core::ValueType lastSmartType_{core::ValueType::Int32};
    QString lastSmartSource_;
    QComboBox *settingsTypeCombo_{};
    QComboBox *settingsModeCombo_{};
    QCheckBox *settingsFastScanCheck_{};
    QCheckBox *settingsSkipMaskedCheck_{};
    QCheckBox *settingsAutoRefreshCheck_{};
    QSpinBox *settingsRefreshIntervalSpin_{};
    QSpinBox *sparkDurationSpin_{};
    QCheckBox *startMaximizedCheck_{};
    QCheckBox *confirmDetachCheck_{};
    QCheckBox *notesVisibleCheck_{};
    bool confirmDetach_{true};
    bool keepNotesVisible_{false};

    static MainWindow *instance_;
    friend class ScanResultsModel;

public:
    static MainWindow *instance() { return instance_; }
    void openAutoAssemblerAt(uintptr_t address, const std::vector<uint8_t> &bytes = {});
    void openAobInjectionAt(uintptr_t address);
    void openPointerScannerAt(uintptr_t address);
    void updateGlobalAddress(uintptr_t address, core::ValueType typeHint = core::ValueType::Int32,
                             const QString &source = QString());
};
