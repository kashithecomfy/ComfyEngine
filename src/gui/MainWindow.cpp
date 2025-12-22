#include "gui/MainWindow.h"

#include <QListView>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QTableWidget>
#include <QTableView>
#include <QHeaderView>
#include <QTextEdit>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QMessageBox>
#include <QApplication>
#include <QGroupBox>
#include <QTimer>
#include <QCheckBox>
#include <QTableWidget>
#include <QTextEdit>
#include <QStackedWidget>
#include <QDialog>
#include <QDialogButtonBox>
#include <QProgressBar>
#include <QThread>
#include <QMenu>
#include <QToolButton>
#include <QSpinBox>
#include <QRegularExpression>
#include <QEvent>
#include <QFileDialog>
#include <QFile>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QToolBar>
#include <QProcess>
#include <QCoreApplication>
#include <QMenuBar>
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QBrush>
#include <QClipboard>
#include <QActionGroup>
#include <QScrollBar>
#include <QStyle>
#include <QFontDatabase>
#include <QCloseEvent>
#include <QSettings>
#include <QPlainTextEdit>
#include <QTreeWidget>
#include <QListWidget>
#include <QList>
#include <QSizePolicy>
#include <QDateTime>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QGraphicsItem>
#include <QGraphicsTextItem>
#include <QPixmap>
#include <QPen>
#include <QBrush>
#include <QScrollArea>
#include <QFormLayout>
#include <QDesktopServices>
#include <QUrl>
#include <QSignalBlocker>
#include <QVariant>

#include <cstring>
#include <fstream>
#include <algorithm>
#include <array>

#include "gui/PointerScannerDialog.h"
#include "gui/AutoAssemblerDialog.h"
#include "gui/ProcessDialog.h"
#include "gui/MemoryViewerWindow.h"
#include "gui/ValueMonitorDialog.h"
#include "gui/WatchWindow.h"
#include "gui/AobInjectionDialog.h"
#include "core/DebugWatch.h"

#include <sstream>
#include <cmath>

namespace {
constexpr const char kSettingsOrg[] = "ComfyKashi";
constexpr const char kSettingsApp[] = "ComfyEngine";
const QUrl kGithubUrl(QStringLiteral("https://github.com/kashithecomfy/ComfyEngine"));
const QUrl kCoffeeUrl(QStringLiteral("https://buymeacoffee.com/comfykashi"));

uintptr_t parseAddress(const QString &s) {
    bool ok = false;
    uintptr_t v = s.toULongLong(&ok, 0);
    return ok ? v : 0;
}

std::vector<uint8_t> parseHexBytes(const QString &s) {
    std::vector<uint8_t> out;
    std::istringstream iss(s.toStdString());
    std::string tok;
    while (iss >> tok) {
        uint8_t b = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
        out.push_back(b);
    }
    return out;
}

QString typeToString(core::ValueType t) {
    switch (t) {
        case core::ValueType::Byte: return "Byte";
        case core::ValueType::Int16: return "2 Bytes";
        case core::ValueType::Int32: return "4 Bytes";
        case core::ValueType::Int64: return "8 Bytes";
        case core::ValueType::Float: return "Float";
        case core::ValueType::Double: return "Double";
        case core::ValueType::ArrayOfByte: return "AOB";
        case core::ValueType::String: return "String";
    }
    return "Unknown";
}

template <typename T>
T unpackRaw(uint64_t raw) {
    T value{};
    std::memcpy(&value, &raw, sizeof(T));
    return value;
}

QString formatRawValue(uint64_t raw, core::ValueType t) {
    switch (t) {
        case core::ValueType::Byte:
            return QString::number(unpackRaw<int8_t>(raw));
        case core::ValueType::Int16:
            return QString::number(unpackRaw<int16_t>(raw));
        case core::ValueType::Int32:
            return QString::number(unpackRaw<int32_t>(raw));
        case core::ValueType::Int64:
            return QString::number(unpackRaw<int64_t>(raw));
        case core::ValueType::Float:
            return QString::number(unpackRaw<float>(raw), 'g', 6);
        case core::ValueType::Double:
            return QString::number(unpackRaw<double>(raw), 'g', 12);
        case core::ValueType::ArrayOfByte:
        case core::ValueType::String:
            return QString();
    }
    return QString();
}

QString formatValue(const QByteArray &data, core::ValueType t) {
    if (data.isEmpty()) return "";
    switch (t) {
        case core::ValueType::Byte:
            if (data.size() == static_cast<int>(sizeof(int8_t))) { int8_t v; std::memcpy(&v, data.data(), sizeof(v)); return QString::number(v); }
            break;
        case core::ValueType::Int16:
            if (data.size() == static_cast<int>(sizeof(int16_t))) { int16_t v; std::memcpy(&v, data.data(), sizeof(v)); return QString::number(v); }
            break;
        case core::ValueType::Int32:
            if (data.size() == static_cast<int>(sizeof(int32_t))) { int32_t v; std::memcpy(&v, data.data(), sizeof(v)); return QString::number(v); }
            break;
        case core::ValueType::Int64:
            if (data.size() == static_cast<int>(sizeof(int64_t))) { int64_t v; std::memcpy(&v, data.data(), sizeof(v)); return QString::number(v); }
            break;
        case core::ValueType::Float:
            if (data.size() == static_cast<int>(sizeof(float))) { float v; std::memcpy(&v, data.data(), sizeof(v)); return QString::number(v, 'g', 6); }
            break;
        case core::ValueType::Double:
            if (data.size() == static_cast<int>(sizeof(double))) { double v; std::memcpy(&v, data.data(), sizeof(v)); return QString::number(v, 'g', 12); }
            break;
        case core::ValueType::ArrayOfByte:
            return QString::fromLatin1(data.toHex(' '));
        case core::ValueType::String:
            return QString::fromLatin1(data);
    }
    return "";
}

QString ptraceHint() {
    std::ifstream f("/proc/sys/kernel/yama/ptrace_scope");
    int scope = -1;
    if (f.good()) {
        f >> scope;
    }
    if (scope > 0) {
        return QString("\nHint: ptrace_scope=%1; try 'echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope' or run as root.")
            .arg(scope);
    }
    return QString();
}

}

class ScanResultsModel : public QAbstractTableModel {
public:
    explicit ScanResultsModel(MainWindow *owner)
        : QAbstractTableModel(owner), owner_(owner) {}

    int rowCount(const QModelIndex &parent = QModelIndex()) const override {
        if (parent.isValid() || !owner_) return 0;
        return owner_->resultRowCount();
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override {
        Q_UNUSED(parent);
        return 5;
    }

    QVariant data(const QModelIndex &index, int role) const override {
        if (!owner_ || !index.isValid()) return QVariant();
        return owner_->resultData(index.row(), index.column(), role);
    }

    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
            switch (section) {
                case 0: return "Address";
                case 1: return "Value";
                case 2: return "Previous";
                case 3: return "First";
                case 4: return "Type";
            }
        }
        return QVariant();
    }

    Qt::ItemFlags flags(const QModelIndex &index) const override {
        if (!index.isValid()) return Qt::NoItemFlags;
        return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    }

    void resetModel() {
        beginResetModel();
        endResetModel();
    }

    void notifyRowsChanged(const std::vector<int> &rows) {
        for (int row : rows) {
            if (row < 0 || row >= rowCount()) continue;
            auto start = index(row, 0);
            auto end = index(row, 4);
            emit dataChanged(start, end, {Qt::DisplayRole, Qt::ForegroundRole});
        }
    }

private:
    MainWindow *owner_;
};

MainWindow *MainWindow::instance_ = nullptr;

class ScanWorker : public QObject {
public:
    enum class Kind { First, Next };
    ScanWorker(core::MemoryScanner *scanner, const core::ScanParams &params, Kind kind,
               std::atomic<size_t> *progressDone = nullptr, size_t progressTotal = 0)
        : scanner_(scanner), params_(params), kind_(kind), progressDone_(progressDone), progressTotal_(progressTotal) {}

public:
    void run() {
        bool ok = false;
        if (scanner_) {
            scanner_->setProgressSink(progressDone_, progressTotal_);
            if (kind_ == Kind::First) ok = scanner_->firstScan(params_);
            else ok = scanner_->nextScan(params_);
            scanner_->setProgressSink(nullptr, 0);
        }
        success = ok;
    }

    bool success{false};
    std::atomic<size_t> *progressDone_{};
    size_t progressTotal_{0};

private:
    core::MemoryScanner *scanner_;
    core::ScanParams params_;
    Kind kind_;
};

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    instance_ = this;
    setupUi();
}

MainWindow::~MainWindow() {
    if (instance_ == this) instance_ = nullptr;
}

void MainWindow::setupUi() {
    setDockOptions(QMainWindow::AllowNestedDocks | QMainWindow::AllowTabbedDocks);
    freezeTimer_ = new QTimer(this);
    freezeTimer_->setInterval(50);
    connect(freezeTimer_, &QTimer::timeout, this, [this]() {
        if (!target_) return;
        for (const auto &w : watches_) {
            if (!w.frozen || w.stored.isEmpty()) continue;
            uintptr_t effectiveAddr = w.address;
            if (w.isPointer && !w.offsets.empty()) {
                effectiveAddr = resolvePointerChain(w.address, w.offsets);
            }
            if (effectiveAddr != 0) {
                target_->writeMemory(effectiveAddr, w.stored.data(), static_cast<size_t>(w.stored.size()));
            }
        }
    });
    watchRefreshTimer_ = new QTimer(this);
    watchRefreshTimer_->setInterval(250);
    connect(watchRefreshTimer_, &QTimer::timeout, this, [this]() {
        refreshResultValues();
        refreshWatchValues();
    });

    statusLabel_ = new QLabel("No process", this);
    statusBase_ = QStringLiteral("No process");
    statusDetail_.clear();

    valueEdit_ = new QLineEdit(this);
    valueEdit2_ = new QLineEdit(this);
    typeCombo_ = new QComboBox(this);
    typeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "Array of Byte", "String"});
    typeCombo_->setCurrentIndex(2);
    modeCombo_ = new QComboBox(this);
    modeCombo_->addItems({"Exact", "Unknown", "Changed", "Unchanged", "Increased", "Decreased", "Greater Than", "Less Than", "Between", "AOB"});
    connect(modeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        core::ScanMode mode = static_cast<core::ScanMode>(index);
        bool needsValue = (mode == core::ScanMode::Exact || 
                           mode == core::ScanMode::GreaterThan || 
                           mode == core::ScanMode::LessThan || 
                           mode == core::ScanMode::Changed || // Changed can take a value for "Changed by"
                           mode == core::ScanMode::Increased || 
                           mode == core::ScanMode::Decreased);
        
        bool needsTwoValues = (mode == core::ScanMode::Between);
        
        // Some modes like UnknownInitial, Unchanged, Aob might behave differently
        // But for generic UI updates:
        
        if (mode == core::ScanMode::UnknownInitial) {
            valueEdit_->setEnabled(false);
            valueEdit2_->setEnabled(false);
        } else if (mode == core::ScanMode::Between) {
            valueEdit_->setEnabled(true);
            valueEdit2_->setEnabled(true);
        } else {
            // For Exact and others, enable first box
            valueEdit_->setEnabled(true);
            valueEdit2_->setEnabled(false);
        }
        
        if (mode == core::ScanMode::Aob) {
             valueEdit_->setPlaceholderText("e.g. 90 90 ?? FF");
        } else {
             valueEdit_->setPlaceholderText("");
        }
    });
    
    hexCheck_ = new QCheckBox("Hex", this);
    firstScanBtn_ = new QPushButton("First Scan", this);
    nextScanBtn_ = new QPushButton("Next Scan", this);
    undoScanBtn_ = new QPushButton("Undo Scan", this);
    undoScanBtn_->setEnabled(false);
    scanProgress_ = new QProgressBar(this);
    scanProgress_->setRange(0, 0);
    scanProgress_->setVisible(false);
    stopScanBtn_ = new QPushButton("Stop Scan", this);
    stopScanBtn_->setEnabled(false);

    resultsModel_ = new ScanResultsModel(this);
    resultsProxy_ = new QSortFilterProxyModel(this);
    resultsProxy_->setSourceModel(resultsModel_);
    resultsProxy_->setSortRole(Qt::UserRole);
    resultsProxy_->setDynamicSortFilter(true);
    resultsTable_ = new QTableView(this);
    resultsTable_->setModel(resultsProxy_);
    resultsTable_->setSortingEnabled(true);
    resultsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    resultsTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    resultsTable_->setAlternatingRowColors(true);
    resultsTable_->setShowGrid(false);
    resultsTable_->setMouseTracking(true);
    resultsTable_->verticalHeader()->setVisible(false);
    resultsTable_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    resultsTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    resultsTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    resultsTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    resultsTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    resultsTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    resultsTable_->horizontalHeader()->setHighlightSections(false);
    updateResultColumnVisibility();

    newValueEdit_ = new QLineEdit(this);
    modifyBtn_ = new QPushButton("Set value", this);
    freezeCheck_ = new QCheckBox("Freeze selected", this);
    unfreezeBtn_ = new QPushButton("Unfreeze all", this);

    patchAddressEdit_ = new QLineEdit(this);
    patchBytesEdit_ = new QLineEdit(this);
    patchBtn_ = new QPushButton("Patch Bytes", this);
    restoreBtn_ = new QPushButton("Restore", this);

    watchTable_ = new QTableWidget(this);
    watchTable_->setColumnCount(6);
    watchTable_->setHorizontalHeaderLabels({"Freeze", "Description", "Address", "Type", "Value", "Ptr"});
    watchTable_->horizontalHeader()->setStretchLastSection(true);
    watchTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    watchTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    watchTable_->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::SelectedClicked);
    watchTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    watchTable_->setAlternatingRowColors(true);
    watchTable_->setShowGrid(false);
    watchTable_->verticalHeader()->setVisible(false);
    watchTable_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    watchTable_->setMouseTracking(true);
    watchTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    watchTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    watchTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    watchTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    watchTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    watchTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    addWatchBtn_ = new QPushButton("Add from scan", this);
    removeWatchBtn_ = new QPushButton("Delete", this);
    updateWatchBtn_ = new QPushButton("Apply", this);
    watchValueEdit_ = new QLineEdit(this);
    watchValueEdit_->installEventFilter(this);
    connect(watchValueEdit_, &QLineEdit::textEdited, this, [this](const QString &) {
        watchValueEditing_ = true;
    });
    connect(watchValueEdit_, &QLineEdit::editingFinished, this, [this]() {
        watchValueEditing_ = false;
    });
    saveTableBtn_ = new QPushButton("Save table...", this);
    loadTableBtn_ = new QPushButton("Load table...", this);
    refreshValuesBtn_ = new QPushButton("Refresh now", this);
    autoRefreshCheck_ = new QCheckBox("Auto refresh", this);
    autoRefreshCheck_->setChecked(true);
    refreshIntervalSpin_ = new QSpinBox(this);
    refreshIntervalSpin_->setRange(50, 5000);
    refreshIntervalSpin_->setSingleStep(50);
    refreshIntervalSpin_->setValue(250);
    refreshIntervalSpin_->setSuffix(" ms");

    scanProgressTimer_ = new QTimer(this);
    scanProgressTimer_->setInterval(100);

    auto scanBox = new QGroupBox("Memory Scan", this);
    auto scanGrid = new QGridLayout;
    scanGrid->setContentsMargins(0, 0, 0, 0);
    scanGrid->setHorizontalSpacing(8);
    scanGrid->setVerticalSpacing(6);
    scanGrid->addWidget(new QLabel("Value", this), 0, 0);
    scanGrid->addWidget(valueEdit_, 0, 1);
    scanGrid->addWidget(new QLabel("Scan Type", this), 0, 2);
    scanGrid->addWidget(modeCombo_, 0, 3);
    scanGrid->addWidget(new QLabel("Value Type", this), 1, 0);
    scanGrid->addWidget(typeCombo_, 1, 1);
    scanGrid->addWidget(new QLabel("Value 2", this), 1, 2);
    scanGrid->addWidget(valueEdit2_, 1, 3);
    scanGrid->addWidget(hexCheck_, 2, 0);
    scanGrid->addWidget(undoScanBtn_, 2, 1);
    scanGrid->addWidget(firstScanBtn_, 2, 2);
    scanGrid->addWidget(nextScanBtn_, 2, 3);

    writableCheck_ = new QCheckBox("Writable", this);
    executableCheck_ = new QCheckBox("Executable", this);
    skipMaskedCheck_ = new QCheckBox("Skip masked regions", this);
    skipMaskedCheck_->setChecked(true);
    fastScanCheck_ = new QCheckBox("Fast scan alignment", this);
    fastScanCheck_->setChecked(true);
    alignmentEdit_ = new QLineEdit(this);
    startAddrEdit_ = new QLineEdit(this);
    endAddrEdit_ = new QLineEdit(this);
    auto advGrid = new QGridLayout;
    advGrid->setContentsMargins(0, 0, 0, 0);
    advGrid->setHorizontalSpacing(8);
    advGrid->setVerticalSpacing(6);
    advGrid->addWidget(writableCheck_, 0, 0);
    advGrid->addWidget(executableCheck_, 0, 1);
    advGrid->addWidget(skipMaskedCheck_, 0, 2, 1, 2);
    advGrid->addWidget(fastScanCheck_, 1, 0, 1, 2);
    advGrid->addWidget(new QLabel("Alignment", this), 1, 2);
    advGrid->addWidget(alignmentEdit_, 1, 3);
    advGrid->addWidget(new QLabel("Start Addr", this), 2, 0);
    advGrid->addWidget(startAddrEdit_, 2, 1);
    advGrid->addWidget(new QLabel("End Addr", this), 2, 2);
    advGrid->addWidget(endAddrEdit_, 2, 3);

    auto advBox = new QGroupBox("Memory Scan Options", this);
    advBox->setLayout(advGrid);

    auto scanLayout = new QVBoxLayout;
    scanLayout->setContentsMargins(8, 8, 8, 8);
    scanLayout->setSpacing(6);
    scanLayout->addLayout(scanGrid);
    scanLayout->addWidget(advBox);
    auto *scanProgressRow = new QHBoxLayout;
    scanProgressRow->addWidget(scanProgress_);
    scanProgressRow->addStretch();
    scanProgressRow->addWidget(stopScanBtn_);
    scanLayout->addLayout(scanProgressRow);
    scanBox->setLayout(scanLayout);
    scanBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);

    auto resultsBox = new QGroupBox("Address List", this);
    auto resultsLayout = new QVBoxLayout;
    resultsLayout->setContentsMargins(8, 8, 8, 8);
    resultsLayout->setSpacing(6);
    auto *resultsControls = new QHBoxLayout;
    resultsControls->setContentsMargins(0, 0, 0, 0);
    resultsControls->setSpacing(8);
    resultsControls->addWidget(refreshValuesBtn_);
    resultsControls->addWidget(autoRefreshCheck_);
    resultsControls->addWidget(new QLabel("Interval", this));
    resultsControls->addWidget(refreshIntervalSpin_);
    resultsCountLabel_ = new QLabel("0 results", this);
    resultsCountLabel_->setStyleSheet("color:#7fdcff;font-weight:bold;");
    resultsControls->addWidget(resultsCountLabel_);
    resultsControls->addStretch();
    resultsLayout->addLayout(resultsControls);
    resultsLayout->addWidget(resultsTable_);
    resultsBox->setLayout(resultsLayout);
    resultsBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    auto editBox = new QGroupBox("Cheat Table", this);
    auto cheatLayout = new QVBoxLayout;
    cheatLayout->setContentsMargins(8, 8, 8, 8);
    cheatLayout->setSpacing(6);
    cheatLayout->addWidget(watchTable_);
    auto editLayout = new QHBoxLayout;
    editLayout->setSpacing(6);
    editLayout->addWidget(new QLabel("Value"));
    editLayout->addWidget(watchValueEdit_);
    editLayout->addWidget(updateWatchBtn_);
    editLayout->addWidget(freezeCheck_);
    editLayout->addWidget(unfreezeBtn_);
    editLayout->addWidget(addWatchBtn_);
    editLayout->addWidget(removeWatchBtn_);
    editLayout->addWidget(saveTableBtn_);
    editLayout->addWidget(loadTableBtn_);
    cheatLayout->addLayout(editLayout);
    editBox->setLayout(cheatLayout);
    editBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    auto patchBox = new QGroupBox("Memory Patch", this);
    auto patchGrid = new QGridLayout;
    patchGrid->setContentsMargins(0, 0, 0, 0);
    patchGrid->setHorizontalSpacing(8);
    patchGrid->setVerticalSpacing(6);
    patchGrid->addWidget(new QLabel("Address"), 0, 0);
    patchGrid->addWidget(patchAddressEdit_, 0, 1, 1, 3);
    patchGrid->addWidget(new QLabel("Bytes (hex)"), 1, 0);
    patchGrid->addWidget(patchBytesEdit_, 1, 1, 1, 2);
    patchGrid->addWidget(patchBtn_, 1, 3);
    patchGrid->addWidget(restoreBtn_, 2, 3);
    patchBox->setLayout(patchGrid);
    patchBox->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);

    mainToolbar_ = addToolBar("Main");
    mainToolbar_->setMovable(false);
    statusLabel_->setStyleSheet("margin-left:12px;color:#7fdcff;font-weight:bold;");
    QWidget *spacer = new QWidget;
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    mainToolbar_->addWidget(spacer);
    mainToolbar_->addWidget(statusLabel_);
    QAction *actSelectProcess = mainToolbar_->addAction("Select process...");
    attachAction_ = mainToolbar_->addAction("Attach");
    QAction *actMemoryViewer = mainToolbar_->addAction("Memory Viewer");
    QAction *actPointerScanner = mainToolbar_->addAction("Pointer Scanner");
    QAction *actAutoAsm = mainToolbar_->addAction("Auto Assembler");
    QAction *actAob = mainToolbar_->addAction("AoB Injection");
    QAction *actLaunchTest = mainToolbar_->addAction("Launch Test Game");
    snapshotAction_ = mainToolbar_->addAction("Snapshot");
    compareSnapshotAction_ = mainToolbar_->addAction("Compare Snapshot");
    mainToolbar_->addSeparator();
    QAction *actSupport = mainToolbar_->addAction("Buy Me a Coffee");

    auto themed = [](const QString &name, QStyle::StandardPixmap fallback) {
        QIcon icon = QIcon::fromTheme(name);
        if (icon.isNull() && QApplication::style()) icon = QApplication::style()->standardIcon(fallback);
        return icon;
    };
    actSelectProcess->setIcon(themed("system-run", QStyle::SP_ComputerIcon));
    if (attachAction_) attachAction_->setIcon(themed("network-connect", QStyle::SP_BrowserReload));
    actMemoryViewer->setIcon(themed("view-visible", QStyle::SP_DirOpenIcon));
    actPointerScanner->setIcon(themed("system-search", QStyle::SP_FileDialogListView));
    actAutoAsm->setIcon(themed("code-context", QStyle::SP_ArrowForward));
    actAob->setIcon(themed("document-new", QStyle::SP_FileDialogDetailedView));
    actLaunchTest->setIcon(themed("media-playback-start", QStyle::SP_MediaPlay));
    actSupport->setIcon(themed("emblem-favorite", QStyle::SP_DialogYesButton));
    centralSpacer_ = new QWidget(this);
    centralSpacer_->setAttribute(Qt::WA_TransparentForMouseEvents);
    centralSpacer_->setMinimumSize(0, 0);
    centralSpacer_->setMaximumSize(0, 0);
    centralSpacer_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setCentralWidget(centralSpacer_);
    setContentsMargins(0, 0, 0, 0);
    setWindowTitle("ComfyEngine");

    auto viewMenu = menuBar()->addMenu("&View");
    auto makeDock = [this, viewMenu](const QString &title, QWidget *content, Qt::DockWidgetArea area) {
        auto *dock = new QDockWidget(title, this);
        dock->setWidget(content);
        dock->setObjectName(title);
        dock->setAllowedAreas(Qt::AllDockWidgetAreas);
        addDockWidget(area, dock);
        if (viewMenu) viewMenu->addAction(dock->toggleViewAction());
        return dock;
    };

    scanDock_ = makeDock("Memory Scan", scanBox, Qt::LeftDockWidgetArea);
    resultsDock_ = makeDock("Scan Results", resultsBox, Qt::RightDockWidgetArea);
    watchDock_ = makeDock("Watch List", editBox, Qt::RightDockWidgetArea);
    patchDock_ = makeDock("Memory Patch", patchBox, Qt::BottomDockWidgetArea);

    notesEdit_ = new QPlainTextEdit(this);
    notesEdit_->setPlaceholderText("Session notes...");
    notesDock_ = makeDock("Notes", notesEdit_, Qt::BottomDockWidgetArea);

    auto *scriptPanel = new QWidget(this);
    auto *scriptLayout = new QVBoxLayout(scriptPanel);
    scriptNameEdit_ = new QLineEdit(scriptPanel);
    scriptNameEdit_->setPlaceholderText("Script description");
    scriptEditor_ = new QPlainTextEdit(scriptPanel);
    scriptEditor_->setPlaceholderText("Write scripts here and send to Auto Assembler...");
    scriptEditor_->setTabStopDistance(4 * scriptEditor_->fontMetrics().horizontalAdvance(' '));
    scriptEditor_->setLineWrapMode(QPlainTextEdit::NoWrap);
    scriptSendBtn_ = new QPushButton("Open in Auto Assembler", scriptPanel);
    scriptLayout->addWidget(scriptNameEdit_);
    auto *editorContainer = new QWidget(scriptPanel);
    auto *editorLayout = new QVBoxLayout(editorContainer);
    editorLayout->setContentsMargins(0, 0, 0, 0);
    editorLayout->setSpacing(6);
    auto *editorToolbar = new QHBoxLayout;
    auto *dropdown = new QComboBox(editorContainer);
    dropdown->addItems({"Code Injection", "AOB Injection", "Pointer Setter", "Empty"});
    editorToolbar->addWidget(new QLabel("Template"));
    editorToolbar->addWidget(dropdown);
    editorToolbar->addStretch();
    auto *previewBtn = new QPushButton("Preview", editorContainer);
    editorToolbar->addWidget(previewBtn);
    editorLayout->addLayout(editorToolbar);
    editorLayout->addWidget(scriptEditor_);
    scriptLayout->addWidget(editorContainer);
    auto *templatePreview = new QPlainTextEdit(scriptPanel);
    templatePreview->setReadOnly(true);
    templatePreview->setMaximumHeight(120);
    templatePreview->setPlaceholderText("Auto Assembler preview...");
    scriptLayout->addWidget(templatePreview);
    scriptLayout->addWidget(scriptSendBtn_);
    auto renderTemplate = [this, templatePreview, dropdown]() {
        QString base = dropdown->currentText();
        QString code;
        if (base == "Code Injection") {
            code = makePatchScript(globalAddress_, QStringLiteral("90 90 90 90 90"));
        } else if (base == "AOB Injection") {
            code = makePatchScript(globalAddress_, QStringLiteral("90 90 90 90 90"), true);
        } else if (base == "Pointer Setter") {
            code = makePatchScript(globalAddress_, QStringLiteral("00 00 00 00 00 00 00 00"));
        }
        if (code.isEmpty()) {
            code = QStringLiteral("[ENABLE]\n\n[DISABLE]\n");
        }
        templatePreview->setPlainText(code);
    };
    renderTemplate();

    connect(dropdown, &QComboBox::currentTextChanged, this, [renderTemplate](const QString &) {
        renderTemplate();
    });
    connect(scriptSendBtn_, &QPushButton::clicked, this, [this]() {
        openAutoAssemblerAt(globalAddress_);
        if (autoAsm_) {
            QString name = scriptNameEdit_ ? scriptNameEdit_->text().trimmed() : QStringLiteral("Dock Script");
            if (name.isEmpty()) name = QStringLiteral("Dock Script");
            autoAsm_->setScriptForEditing(name, scriptEditor_ ? scriptEditor_->toPlainText() : QString());
        }
    });
    scriptDock_ = makeDock("Script Editor", scriptPanel, Qt::BottomDockWidgetArea);

    memoryViewer_ = new MemoryViewerWindow(this);
    memoryViewerDock_ = makeDock("Memory Viewer", memoryViewer_, Qt::RightDockWidgetArea);

    trackingList_ = new QTreeWidget(this);
    trackingList_->setColumnCount(2);
    trackingList_->setHeaderLabels({"Address", "Value"});
    trackingList_->setRootIsDecorated(false);
    trackingList_->setAlternatingRowColors(true);
    trackingList_->setContextMenuPolicy(Qt::CustomContextMenu);
    trackingDock_ = makeDock("Tracked Values", trackingList_, Qt::RightDockWidgetArea);
    trackingDock_->hide();
    connect(trackingList_, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem *item, int) {
        if (!item) return;
        bool ok = false;
        uintptr_t addr = item->text(0).toULongLong(&ok, 0);
        if (!ok) return;
        core::ValueType type = resultDisplayType_;
        if (auto it = trackedTypes_.find(addr); it != trackedTypes_.end()) type = it->second;
        updateGlobalAddress(addr, type, QStringLiteral("Tracked"));
    });
    connect(trackingList_, &QWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        if (!trackingList_) return;
        auto *item = trackingList_->itemAt(pos);
        QMenu menu(this);
        QAction *removeAct = menu.addAction("Remove");
        QAction *clearAct = menu.addAction("Clear All");
        QAction *chosen = menu.exec(trackingList_->viewport()->mapToGlobal(pos));
        if (!chosen) return;
        if (chosen == removeAct && item) {
            bool ok = false;
            uintptr_t addr = item->text(0).toULongLong(&ok, 0);
            if (ok) {
                trackedAddresses_.erase(addr);
                trackedTypes_.erase(addr);
            }
            delete item;
            updateTrackedEntries();
        } else if (chosen == clearAct) {
            trackedAddresses_.clear();
            trackedTypes_.clear();
            trackingList_->clear();
            updateTrackedEntries();
        }
    });

    smartPanel_ = new QPlainTextEdit(this);
    smartPanel_->setReadOnly(true);
    smartDock_ = makeDock("Context", smartPanel_, Qt::RightDockWidgetArea);
    smartDock_->hide();

    pointerScene_ = new QGraphicsScene(this);
    pointerGraphView_ = new QGraphicsView(pointerScene_, this);
    pointerGraphView_->setRenderHint(QPainter::Antialiasing);
    pointerGraphView_->setMinimumHeight(200);
    pointerDock_ = makeDock("Pointer Graph", pointerGraphView_, Qt::RightDockWidgetArea);
    pointerDock_->hide();

    memoryScene_ = new QGraphicsScene(this);
    memoryVizView_ = new QGraphicsView(memoryScene_, this);
    memoryVizView_->setMinimumHeight(220);
    memoryVizDock_ = makeDock("Memory Visualization", memoryVizView_, Qt::RightDockWidgetArea);
    memoryVizDock_->hide();

    auto *settingsContainer = new QWidget(this);
    auto *settingsLayout = new QVBoxLayout(settingsContainer);
    settingsLayout->setContentsMargins(12, 12, 12, 12);
    settingsLayout->setSpacing(12);

    auto *generalGroup = new QGroupBox("General", settingsContainer);
    auto *generalLayout = new QVBoxLayout(generalGroup);
    startMaximizedCheck_ = new QCheckBox("Launch ComfyEngine maximized", generalGroup);
    confirmDetachCheck_ = new QCheckBox("Ask before detaching from a process", generalGroup);
    notesVisibleCheck_ = new QCheckBox("Keep Session Notes dock visible", generalGroup);
    generalLayout->addWidget(startMaximizedCheck_);
    generalLayout->addWidget(confirmDetachCheck_);
    generalLayout->addWidget(notesVisibleCheck_);
    generalGroup->setLayout(generalLayout);
    settingsLayout->addWidget(generalGroup);

    auto *scanGroup = new QGroupBox("Scanning Defaults", settingsContainer);
    auto *scanForm = new QFormLayout(scanGroup);
    settingsTypeCombo_ = new QComboBox(scanGroup);
    settingsTypeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "Array of Byte", "String"});
    settingsModeCombo_ = new QComboBox(scanGroup);
    settingsModeCombo_->addItems({"Exact", "Unknown", "Changed", "Unchanged", "Increased", "Decreased",
                                  "Greater Than", "Less Than", "Between", "AOB"});
    settingsFastScanCheck_ = new QCheckBox("Enable fast scan optimizations", scanGroup);
    settingsSkipMaskedCheck_ = new QCheckBox("Skip values masked by filters", scanGroup);
    scanForm->addRow("Value type", settingsTypeCombo_);
    scanForm->addRow("Scan mode", settingsModeCombo_);
    scanForm->addRow(settingsFastScanCheck_);
    scanForm->addRow(settingsSkipMaskedCheck_);
    scanGroup->setLayout(scanForm);
    settingsLayout->addWidget(scanGroup);

    auto *watchGroup = new QGroupBox("Watch List", settingsContainer);
    auto *watchForm = new QFormLayout(watchGroup);
    settingsAutoRefreshCheck_ = new QCheckBox("Auto refresh watch list", watchGroup);
    settingsRefreshIntervalSpin_ = new QSpinBox(watchGroup);
    settingsRefreshIntervalSpin_->setRange(50, 5000);
    settingsRefreshIntervalSpin_->setSingleStep(50);
    settingsRefreshIntervalSpin_->setSuffix(" ms");
    sparkDurationSpin_ = new QSpinBox(watchGroup);
    sparkDurationSpin_->setRange(120, 6000);
    sparkDurationSpin_->setSingleStep(30);
    sparkDurationSpin_->setSuffix(" ms");
    watchForm->addRow(settingsAutoRefreshCheck_);
    watchForm->addRow("Refresh interval", settingsRefreshIntervalSpin_);
    watchForm->addRow("Spark highlight", sparkDurationSpin_);
    watchGroup->setLayout(watchForm);
    settingsLayout->addWidget(watchGroup);
    settingsLayout->addStretch();

    auto *settingsScroll = new QScrollArea(this);
    settingsScroll->setWidget(settingsContainer);
    settingsScroll->setWidgetResizable(true);
    settingsDock_ = makeDock("Settings", settingsScroll, Qt::RightDockWidgetArea);
    settingsDock_->hide();

    auto *aboutPanel = new QWidget(this);
    auto *aboutLayout = new QVBoxLayout(aboutPanel);
    aboutLayout->setContentsMargins(16, 16, 16, 16);
    aboutLayout->setSpacing(12);
    auto *aboutTitle = new QLabel("<h2>About ComfyEngine</h2>", aboutPanel);
    aboutTitle->setTextFormat(Qt::RichText);
    aboutLayout->addWidget(aboutTitle);
    auto *aboutText = new QLabel(
        "ComfyEngine is a playground for memory scanning experiments built by ComfyKashi.<br>"
        "If you run into issues or want to contribute, visit the GitHub page below.<br><br>"
        "Want to keep the project alive? Buy a coffee and help fuel future updates!",
        aboutPanel);
    aboutText->setWordWrap(true);
    aboutText->setTextFormat(Qt::RichText);
    aboutText->setTextInteractionFlags(Qt::TextBrowserInteraction);
    aboutText->setOpenExternalLinks(true);
    aboutLayout->addWidget(aboutText);
    auto *linksLayout = new QHBoxLayout;
    auto *githubBtn = new QPushButton("Open GitHub", aboutPanel);
    auto *coffeeBtn = new QPushButton("Buy Me a Coffee", aboutPanel);
    connect(githubBtn, &QPushButton::clicked, this, []() { QDesktopServices::openUrl(kGithubUrl); });
    connect(coffeeBtn, &QPushButton::clicked, this, []() { QDesktopServices::openUrl(kCoffeeUrl); });
    linksLayout->addWidget(githubBtn);
    linksLayout->addWidget(coffeeBtn);
    linksLayout->addStretch();
    aboutLayout->addLayout(linksLayout);
    auto *linkLabel = new QLabel(
        QStringLiteral("<a href=\"%1\">%1</a><br><a href=\"%2\">%2</a>")
            .arg(kGithubUrl.toString(), kCoffeeUrl.toString()),
        aboutPanel);
    linkLabel->setTextFormat(Qt::RichText);
    linkLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
    linkLabel->setOpenExternalLinks(true);
    aboutLayout->addWidget(linkLabel);
    aboutLayout->addStretch();
    aboutDock_ = makeDock("About", aboutPanel, Qt::RightDockWidgetArea);
    aboutDock_->hide();

    sidebarList_ = new QListWidget(this);
    sidebarList_->addItems(
        {"Scanner", "Memory", "Code", "Regions", "Threads", "Symbols", "Scripts", "Dissector", "Tools", "Settings", "About"});
    sidebarList_->setSelectionMode(QAbstractItemView::SingleSelection);
    sidebarDock_ = makeDock("Navigator", sidebarList_, Qt::LeftDockWidgetArea);
    connect(sidebarList_, &QListWidget::currentTextChanged, this, &MainWindow::activateModule);
    sidebarList_->setCurrentRow(0);

    splitDockWidget(sidebarDock_, scanDock_, Qt::Horizontal);
    splitDockWidget(scanDock_, resultsDock_, Qt::Horizontal);
    splitDockWidget(resultsDock_, watchDock_, Qt::Vertical);
    splitDockWidget(watchDock_, patchDock_, Qt::Vertical);
    tabifyDockWidget(resultsDock_, memoryViewerDock_);
    tabifyDockWidget(notesDock_, scriptDock_);
    notesDock_->hide();
    scriptDock_->hide();
    memoryViewerDock_->hide();
    patchDock_->hide();

    QList<int> widths = {120, 420};
    QList<QDockWidget *> docks = {sidebarDock_, scanDock_};
    resizeDocks(docks, widths, Qt::Horizontal);
    QList<int> heights = {350, 160};
    QList<QDockWidget *> vertical = {resultsDock_, watchDock_};
    resizeDocks(vertical, heights, Qt::Vertical);

    loadSettings();
    applyGlobalStyle();
    updateAttachUi();
    updateResultsCount();

    sparkTimer_ = new QTimer(this);
    sparkTimer_->setInterval(120);
    connect(sparkTimer_, &QTimer::timeout, this, [this]() {
        if (sparkTimes_.empty()) return;
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        bool changed = false;
        for (auto it = sparkTimes_.begin(); it != sparkTimes_.end();) {
            if (now - it->second > sparkWindowMs_) {
                it = sparkTimes_.erase(it);
                changed = true;
            } else {
                ++it;
            }
        }
        if (changed && resultsTable_) resultsTable_->viewport()->update();
    });
    sparkTimer_->start();

    connect(refreshValuesBtn_, &QPushButton::clicked, this, [this]() {
        refreshResultValues();
        refreshWatchValues(true);
    });
    connect(autoRefreshCheck_, &QCheckBox::toggled, this, [this](bool enabled) {
        if (enabled) {
            watchRefreshTimer_->start(refreshIntervalSpin_->value());
        } else {
            watchRefreshTimer_->stop();
        }
        if (settingsAutoRefreshCheck_) {
            QSignalBlocker blocker(settingsAutoRefreshCheck_);
            settingsAutoRefreshCheck_->setChecked(enabled);
        }
        persistSetting("watch/autoRefresh", enabled);
    });
    connect(stopScanBtn_, &QPushButton::clicked, this, [this]() {
        if (scanner_) {
            scanner_->requestCancel();
        }
        stopScanBtn_->setEnabled(false);
    });
    connect(refreshIntervalSpin_, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
        watchRefreshTimer_->setInterval(v);
        if (autoRefreshCheck_->isChecked()) {
            watchRefreshTimer_->start(v);
        }
        if (settingsRefreshIntervalSpin_) {
            QSignalBlocker blocker(settingsRefreshIntervalSpin_);
            settingsRefreshIntervalSpin_->setValue(v);
        }
        persistSetting("watch/interval", v);
    });
    if (autoRefreshCheck_->isChecked()) {
        watchRefreshTimer_->start(refreshIntervalSpin_->value());
    }

    connect(startMaximizedCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        persistSetting("ui/startMaximized", checked);
        if (checked) showMaximized();
        else showNormal();
    });
    connect(confirmDetachCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        confirmDetach_ = checked;
        persistSetting("ui/confirmDetach", checked);
    });
    connect(notesVisibleCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        keepNotesVisible_ = checked;
        persistSetting("ui/notesVisible", checked);
        if (notesDock_) {
            if (checked) notesDock_->show();
            else notesDock_->hide();
        }
    });
    connect(settingsTypeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (typeCombo_) typeCombo_->setCurrentIndex(index);
        persistSetting("scan/defaultTypeIndex", index);
    });
    connect(settingsModeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (modeCombo_) modeCombo_->setCurrentIndex(index);
        persistSetting("scan/defaultModeIndex", index);
    });
    connect(settingsFastScanCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        if (fastScanCheck_) fastScanCheck_->setChecked(checked);
        persistSetting("scan/fastScan", checked);
    });
    connect(settingsSkipMaskedCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        if (skipMaskedCheck_) skipMaskedCheck_->setChecked(checked);
        persistSetting("scan/skipMasked", checked);
    });
    connect(settingsAutoRefreshCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        if (autoRefreshCheck_) autoRefreshCheck_->setChecked(checked);
    });
    connect(settingsRefreshIntervalSpin_, qOverload<int>(&QSpinBox::valueChanged), this, [this](int value) {
        if (refreshIntervalSpin_) refreshIntervalSpin_->setValue(value);
    });
    connect(sparkDurationSpin_, qOverload<int>(&QSpinBox::valueChanged), this, [this](int value) {
        sparkWindowMs_ = static_cast<qint64>(value);
        persistSetting("watch/sparkDuration", value);
    });

    auto pointerScannerInvoker = [this]() {
        if (!target_ || !target_->isAttached()) return;
        uintptr_t baseAddr = 0;
        if (watchTable_) {
            auto idx = watchTable_->currentIndex();
            if (idx.isValid()) {
                int row = idx.row();
                if (row >= 0 && row < static_cast<int>(watches_.size())) {
                    const auto &w = watches_[row];
                    if (!w.isScript) baseAddr = w.address;
                }
            }
        }
        if (baseAddr == 0 && resultsTable_ && resultsProxy_) {
            auto resIdx = resultsTable_->currentIndex();
            if (resIdx.isValid()) {
                auto srcIdx = resultsProxy_->mapToSource(resIdx);
                int row = srcIdx.row();
                if (row >= 0 && scanner_ && row < static_cast<int>(scanner_->results().size())) {
                    baseAddr = scanner_->results()[row].address;
                }
            }
        }
        if (baseAddr == 0) baseAddr = globalAddress_;
        openPointerScannerAt(baseAddr);
    };
    auto autoAssemblerInvoker = [this]() {
        bool addrOk = false;
        uintptr_t addr = patchAddressEdit_ ? patchAddressEdit_->text().trimmed().toULongLong(&addrOk, 0) : 0;
        std::vector<uint8_t> bytes;
        if (patchBytesEdit_) {
            const auto parts = patchBytesEdit_->text().trimmed()
                                   .split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            for (const auto &part : parts) {
                bool bOk = false;
                auto val = part.toUInt(&bOk, 16);
                if (!bOk) { bytes.clear(); break; }
                bytes.push_back(static_cast<uint8_t>(val & 0xFF));
            }
        }
        uintptr_t targetAddr = (addrOk && addr != 0) ? addr : globalAddress_;
        openAutoAssemblerAt(targetAddr, bytes);
    };

    connect(actSelectProcess, &QAction::triggered, this, &MainWindow::onProcessClicked);
    connect(attachAction_, &QAction::triggered, this, [this]() {
        if (target_ && target_->isAttached()) {
            bool allowDetach = true;
            if (confirmDetach_) {
                auto reply = QMessageBox::question(this, "Detach",
                                                   "Detach from the current process?",
                                                   QMessageBox::Yes | QMessageBox::No,
                                                   QMessageBox::No);
                allowDetach = (reply == QMessageBox::Yes);
            }
            if (allowDetach) {
                onDetach();
            }
        } else {
            onProcessClicked();
        }
        updateAttachUi();
    });
    connect(actMemoryViewer, &QAction::triggered, this, &MainWindow::onViewMemory);
    connect(actPointerScanner, &QAction::triggered, this, pointerScannerInvoker);
    connect(actAutoAsm, &QAction::triggered, this, autoAssemblerInvoker);
    connect(actLaunchTest, &QAction::triggered, this, &MainWindow::onLaunchTestGame);
    connect(snapshotAction_, &QAction::triggered, this, [this]() { recordSnapshot(); });
    connect(compareSnapshotAction_, &QAction::triggered, this, [this]() { compareSnapshot(); });
    connect(actSupport, &QAction::triggered, this, []() {
        QDesktopServices::openUrl(kCoffeeUrl);
    });
    connect(resultsTable_, &QTableView::doubleClicked, this,
            [this](const QModelIndex &idx) {
                if (!idx.isValid()) return;
                auto sourceIdx = resultsProxy_->mapToSource(idx);
                if (!sourceIdx.isValid()) return;
                resultsTable_->selectionModel()->select(idx, QItemSelectionModel::Rows | QItemSelectionModel::ClearAndSelect);
                onAddWatch();
            });
    connect(resultsTable_, &QTableView::entered, this, [this](const QModelIndex &idx) {
        if (!smartPanel_ || !scanner_ || !idx.isValid()) return;
        auto sourceIdx = resultsProxy_->mapToSource(idx);
        if (!sourceIdx.isValid()) return;
        int row = sourceIdx.row();
        if (row < 0 || row >= static_cast<int>(scanner_->results().size())) return;
        uintptr_t addr = scanner_->results()[row].address;
        updateSmartPanel(addr, resultDisplayType_, QStringLiteral("Scan result"));
    });
    connect(resultsTable_, &QWidget::customContextMenuRequested, this,
            [this](const QPoint &pos) {
                if (!scanner_ || scanner_->results().empty()) return;
                auto proxyIdx = resultsTable_->indexAt(pos);
                if (!proxyIdx.isValid()) return;
                auto sourceIdx = resultsProxy_->mapToSource(proxyIdx);
                if (!sourceIdx.isValid()) return;
                int row = sourceIdx.row();
                if (row < 0 || row >= static_cast<int>(scanner_->results().size())) return;
                uintptr_t addr = scanner_->results()[row].address;

                QMenu menu(this);
                QAction *addAct = menu.addAction("Add to address list");
                QAction *browseAct = menu.addAction("Browse memory region");
                QAction *disasmAct = menu.addAction("Disassemble memory region");
                QAction *writesAct = menu.addAction("Find out what writes to this address");
                QAction *accessAct = menu.addAction("Find out what accesses this address");
                QAction *copyAct = menu.addAction("Copy address");
                QAction *patchAct = menu.addAction("Patch bytes...");
                QAction *trackAct = menu.addAction("Track changes");
                QAction *togglePrevAct = menu.addAction(showPreviousColumn_ ? "Hide \"Previous\" column"
                                                                            : "Show \"Previous\" column");
                QMenu *displayMenu = menu.addMenu("Display as");
                QActionGroup *displayGroup = new QActionGroup(displayMenu);
                displayGroup->setExclusive(true);
                struct Entry { core::ValueType type; const char *label; } entries[] = {
                    {core::ValueType::Byte, "1 Byte"},
                    {core::ValueType::Int16, "2 Bytes"},
                    {core::ValueType::Int32, "4 Bytes"},
                    {core::ValueType::Int64, "8 Bytes"},
                    {core::ValueType::Float, "Float"},
                    {core::ValueType::Double, "Double"}
                };
                std::vector<std::pair<QAction *, core::ValueType>> displayActions;
                for (const auto &entry : entries) {
                    QAction *act = displayMenu->addAction(entry.label);
                    act->setCheckable(true);
                    act->setChecked(resultDisplayType_ == entry.type);
                    act->setActionGroup(displayGroup);
                    displayActions.emplace_back(act, entry.type);
                }

                auto *chosen = menu.exec(resultsTable_->viewport()->mapToGlobal(pos));
                if (!chosen) return;
                if (chosen == addAct) {
                    onAddWatch();
                    return;
                }
                auto openMemoryViewerAt = [this](uintptr_t address) {
                    if (!memoryViewer_ || !target_ || !target_->isAttached()) return;
                    memoryViewer_->setTarget(target_.get(), address);
                    showDock(memoryViewerDock_);
                };
                if (chosen == browseAct || chosen == disasmAct) {
                    openMemoryViewerAt(addr);
                    return;
                }
                if (chosen == writesAct || chosen == accessAct) {
                    if (!target_ || !target_->isAttached()) return;
                    core::WatchType wt = (chosen == writesAct) ? core::WatchType::Writes
                                                               : core::WatchType::Accesses;
                    auto *session = new core::DebugWatchSession(*target_, addr, wt);
                    auto *win = new WatchWindow(session, this);
                    win->setAttribute(Qt::WA_DeleteOnClose);
                    win->show();
                    return;
                }
                if (chosen == copyAct) {
                    QGuiApplication::clipboard()->setText(QString::asprintf("0x%llx",
                        static_cast<unsigned long long>(addr)));
                    return;
                }
                if (chosen == patchAct) {
                    promptPatchBytes(addr);
                    return;
                }
                if (chosen == trackAct) {
                    onTrackValue(addr, resultDisplayType_, QStringLiteral("Scan result"));
                    return;
                }
                if (chosen == togglePrevAct) {
                    showPreviousColumn_ = !showPreviousColumn_;
                    updateResultColumnVisibility();
                    return;
                }
                for (const auto &pair : displayActions) {
                    if (pair.first == chosen) {
                        setResultDisplayType(pair.second);
                        return;
                    }
                }
            });
    connect(resultsTable_->selectionModel(), &QItemSelectionModel::selectionChanged, this,
            [this]() {
                if (!resultsTable_ || !resultsTable_->selectionModel()) return;
                auto rows = resultsTable_->selectionModel()->selectedRows();
                if (rows.isEmpty()) return;
                auto sourceIdx = resultsProxy_->mapToSource(rows.first());
                if (!sourceIdx.isValid()) return;
                updateGlobalAddress(resultAddressForRow(sourceIdx.row()), resultDisplayType_,
                                     QStringLiteral("Scan selection"));
            });
    connect(firstScanBtn_, &QPushButton::clicked, this, &MainWindow::onFirstScan);
    connect(nextScanBtn_, &QPushButton::clicked, this, &MainWindow::onNextScan);
    connect(undoScanBtn_, &QPushButton::clicked, this, &MainWindow::onUndoScan);
    connect(modifyBtn_, &QPushButton::clicked, this, &MainWindow::onModifyValue);
    connect(patchBtn_, &QPushButton::clicked, this, &MainWindow::onPatchBytes);
    connect(restoreBtn_, &QPushButton::clicked, this, &MainWindow::onRestorePatch);
    connect(unfreezeBtn_, &QPushButton::clicked, this, [this]() {
        for (auto &w : watches_) w.frozen = false;
        freezeTimer_->stop();
        populateWatchList(true);
    });
    connect(freezeCheck_, &QCheckBox::toggled, this, [this](bool on) {
        auto selection = watchTable_->selectionModel()->selectedRows();
        if (selection.isEmpty()) return;
        for (const auto &idx : selection) {
            int row = idx.row();
            if (row < 0 || row >= static_cast<int>(watches_.size())) continue;
            watches_[row].frozen = on;
        }
        if (on && !freezeTimer_->isActive()) freezeTimer_->start();
        populateWatchList(true);
    });
    connect(addWatchBtn_, &QPushButton::clicked, this, &MainWindow::onAddWatch);
    connect(removeWatchBtn_, &QPushButton::clicked, this, &MainWindow::onRemoveWatch);
    connect(watchTable_->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this]() {
        if (!watchTable_ || !watchTable_->selectionModel()) return;
        auto rows = watchTable_->selectionModel()->selectedRows();
        if (rows.isEmpty()) return;
        int row = rows.first().row();
        if (row >= 0 && row < static_cast<int>(watches_.size())) {
            auto &w = watches_[row];
            if (!w.isScript && w.address != 0) {
                updateGlobalAddress(w.address, w.type,
                                     w.description.isEmpty() ? QStringLiteral("Cheat entry")
                                                             : w.description);
            }
            if (watchValueEdit_) {
                if (w.isScript) {
                    watchValueEdit_->setText(w.scriptActive ? "Enabled" : "Disabled");
                    watchValueEdit_->setEnabled(false);
                } else {
                    watchValueEdit_->setEnabled(true);
                    watchValueEdit_->clear();
                }
            }
            if (freezeCheck_) freezeCheck_->setEnabled(!w.isScript);
        }
    });
    connect(watchTable_, &QTableWidget::itemEntered, this, [this](QTableWidgetItem *item) {
        if (!smartPanel_ || !item) return;
        int row = item->row();
        if (row < 0 || row >= static_cast<int>(watches_.size())) return;
        auto &w = watches_[row];
        if (w.isScript) return;
        QString source = w.description.isEmpty() ? QStringLiteral("Watch entry") : w.description;
        updateSmartPanel(w.address, w.type, source);
    });
    connect(updateWatchBtn_, &QPushButton::clicked, this, &MainWindow::onUpdateWatchValue);
    auto openAobDialog = [this]() {
        openAobInjectionAt(globalAddress_);
    };
    connect(actAob, &QAction::triggered, this, openAobDialog);
    connect(saveTableBtn_, &QPushButton::clicked, this, &MainWindow::onSaveTable);
    connect(loadTableBtn_, &QPushButton::clicked, this, &MainWindow::onLoadTable);
    connect(watchTable_, &QTableWidget::customContextMenuRequested, this,
            [this](const QPoint &pos) {
                QMenu menu(this);
                auto idx = watchTable_->indexAt(pos);
                if (!idx.isValid()) return;
                int row = idx.row();
                if (row < 0 || row >= static_cast<int>(watches_.size())) return;
                auto &w = watches_[row];
                QAction *chosen = nullptr;
                if (w.isScript) {
                    QAction *toggleAct = menu.addAction(w.scriptActive ? "Disable script" : "Enable script");
                    QAction *editAct = menu.addAction("Edit script...");
                    QAction *deleteAct = menu.addAction("Delete");
                    chosen = menu.exec(watchTable_->viewport()->mapToGlobal(pos));
                    if (!chosen) return;
                    if (chosen == toggleAct) {
                        setScriptState(static_cast<size_t>(row), !w.scriptActive);
                    } else if (chosen == editAct) {
                        openAutoAssemblerAt(globalAddress_);
                        if (autoAsm_) {
                            autoAsm_->setScriptForEditing(w.description, w.scriptSource);
                        }
                    } else if (chosen == deleteAct) {
                        if (w.scriptActive) setScriptState(static_cast<size_t>(row), false);
                        watches_.erase(watches_.begin() + row);
                        populateWatchList(true);
                    }
                    return;
                }

                QAction *freezeAct = menu.addAction("Toggle freeze");
                QAction *monitorValueAct = menu.addAction("Monitor value changes");
                QAction *monitorWritesAct = menu.addAction("Find out what writes to this address");
                QAction *monitorAccessAct = menu.addAction("Find out what accesses this address");
                QAction *browseAct = menu.addAction("Browse this memory");
                QAction *deleteAct = menu.addAction("Delete");
                QAction *trackAct = menu.addAction("Track changes");
                chosen = menu.exec(watchTable_->viewport()->mapToGlobal(pos));
                if (!chosen) return;
                if (chosen == freezeAct) {
                    w.frozen = !w.frozen;
                    if (w.frozen && !freezeTimer_->isActive()) freezeTimer_->start();
                    populateWatchList(true);
                } else if (chosen == monitorValueAct) {
                    if (!target_ || !target_->isAttached()) return;
                    auto *dlg = new ValueMonitorDialog(target_.get(), w.address, w.type, this);
                    dlg->setAttribute(Qt::WA_DeleteOnClose);
                    dlg->show();
                } else if (chosen == monitorWritesAct || chosen == monitorAccessAct) {
                    if (!target_ || !target_->isAttached()) return;
                    core::WatchType wt = (chosen == monitorWritesAct)
                        ? core::WatchType::Writes
                        : core::WatchType::Accesses;
                    auto *session = new core::DebugWatchSession(*target_, w.address, wt);
                    auto *win = new WatchWindow(session, this);
                    win->setAttribute(Qt::WA_DeleteOnClose);
                    win->show();
                } else if (chosen == browseAct) {
                    if (memoryViewer_ && target_ && target_->isAttached()) {
                        memoryViewer_->setTarget(target_.get(), w.address);
                        showDock(memoryViewerDock_);
                    }
                } else if (chosen == trackAct) {
                    QString label = w.description.isEmpty() ? QStringLiteral("Watch entry") : w.description;
                    onTrackValue(w.address, w.type, label);
                } else if (chosen == deleteAct) {
                    watches_.erase(watches_.begin() + row);
                    populateWatchList(true);
                }
            });
    connect(watchTable_, &QTableWidget::cellChanged, this, [this](int row, int column) {
        if (row < 0 || row >= static_cast<int>(watches_.size())) return;
        auto &w = watches_[row];
        if (w.isScript) return;
        if (column == 0) {
            auto *item = watchTable_->item(row, column);
            if (!item) return;
            w.frozen = (item->checkState() == Qt::Checked);
            if (w.frozen && !freezeTimer_->isActive()) freezeTimer_->start();
        } else if (column == 1) {
            auto *item = watchTable_->item(row, column);
            if (!item) return;
            w.description = item->text();
        }
    });
    connect(watchTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int column) {
        if (row < 0 || row >= static_cast<int>(watches_.size())) return;
        auto &w = watches_[row];
        if (w.isScript) {
            setScriptState(static_cast<size_t>(row), !w.scriptActive);
            return;
        }
        if (column == 3) {
            switch (w.type) {
                case core::ValueType::Byte: w.type = core::ValueType::Int16; break;
                case core::ValueType::Int16: w.type = core::ValueType::Int32; break;
                case core::ValueType::Int32: w.type = core::ValueType::Int64; break;
                case core::ValueType::Int64: w.type = core::ValueType::Float; break;
                case core::ValueType::Float: w.type = core::ValueType::Double; break;
                case core::ValueType::Double: w.type = core::ValueType::Byte; break;
                case core::ValueType::ArrayOfByte:
                case core::ValueType::String:
                    w.type = core::ValueType::Byte;
                    break;
            }
            w.stored.clear();
            w.last.clear();
            w.prev.clear();
            populateWatchList(true);
        } else if (column == 4) {
            auto &w = watches_[row];
            QString valStr;
            if (w.type == core::ValueType::Byte && w.stored.size() == static_cast<int>(sizeof(int8_t))) {
                int8_t v;
                std::memcpy(&v, w.stored.data(), sizeof(v));
                valStr = QString::number(v);
            } else if (w.type == core::ValueType::Int16 && w.stored.size() == static_cast<int>(sizeof(int16_t))) {
                int16_t v;
                std::memcpy(&v, w.stored.data(), sizeof(v));
                valStr = QString::number(v);
            } else if (w.type == core::ValueType::Int32 && w.stored.size() == static_cast<int>(sizeof(int32_t))) {
                int32_t v;
                std::memcpy(&v, w.stored.data(), sizeof(v));
                valStr = QString::number(v);
            } else if (w.type == core::ValueType::Int64 && w.stored.size() == static_cast<int>(sizeof(int64_t))) {
                int64_t v;
                std::memcpy(&v, w.stored.data(), sizeof(v));
                valStr = QString::number(v);
            } else if (w.type == core::ValueType::Float && w.stored.size() == static_cast<int>(sizeof(float))) {
                float v;
                std::memcpy(&v, w.stored.data(), sizeof(v));
                valStr = QString::number(v, 'g', 6);
            } else if (w.type == core::ValueType::Double && w.stored.size() == static_cast<int>(sizeof(double))) {
                double v;
                std::memcpy(&v, w.stored.data(), sizeof(v));
                valStr = QString::number(v, 'g', 12);
            }
            if (!valStr.isEmpty() && !watchValueEditing_) {
                watchValueEdit_->setText(valStr);
            }
        }
    });

    updateUndoState();
}

void MainWindow::updateStatus(const QString &text) {
    statusBase_ = text;
    refreshStatusLabel();
}

void MainWindow::setStatusDetail(const QString &text) {
    statusDetail_ = text;
    refreshStatusLabel();
}

void MainWindow::refreshStatusLabel() {
    if (!statusLabel_) return;
    QString display = statusBase_;
    if (!statusDetail_.isEmpty()) {
        if (!display.isEmpty()) display += QStringLiteral(" — ");
        display += statusDetail_;
    }
    statusLabel_->setText(display);
}

void MainWindow::updateAttachUi() {
    if (!attachAction_) return;
    if (target_ && target_->isAttached()) {
        attachAction_->setText("Detach");
    } else {
        attachAction_->setText("Attach");
    }
}

bool MainWindow::eventFilter(QObject *obj, QEvent *event) {
    if (obj == watchValueEdit_) {
        if (event->type() == QEvent::FocusOut) {
            watchValueEditing_ = false;
        }
    }
    return QMainWindow::eventFilter(obj, event);
}

void MainWindow::onLaunchTestGame() {
    QString exeDir = QCoreApplication::applicationDirPath();
    QString candidate = exeDir + "/../testgame/ce-mini-game";
    if (!QFile::exists(candidate)) {
        candidate = exeDir + "/ce-mini-game";
    }
    if (!QFile::exists(candidate)) {
        QMessageBox::warning(this, "Test Game", "Test game executable not found. Build target 'ce-mini-game' first.");
        return;
    }
    QProcess::startDetached(candidate, {});
}

core::ValueType MainWindow::currentValueType() const {
    switch (typeCombo_->currentIndex()) {
        case 0: return core::ValueType::Byte;
        case 1: return core::ValueType::Int16;
        case 2: return core::ValueType::Int32;
        case 3: return core::ValueType::Int64;
        case 4: return core::ValueType::Float;
        case 5: return core::ValueType::Double;
        case 6: return core::ValueType::ArrayOfByte;
        case 7: return core::ValueType::String;
        default: return core::ValueType::Int32;
    }
}

core::ScanMode MainWindow::currentScanMode() const {
    switch (modeCombo_->currentIndex()) {
        case 0: return core::ScanMode::Exact;
        case 1: return core::ScanMode::UnknownInitial;
        case 2: return core::ScanMode::Changed;
        case 3: return core::ScanMode::Unchanged;
        case 4: return core::ScanMode::Increased;
        case 5: return core::ScanMode::Decreased;
        case 6: return core::ScanMode::GreaterThan;
        case 7: return core::ScanMode::LessThan;
        case 8: return core::ScanMode::Between;
        case 9: return core::ScanMode::Aob;
        default: return core::ScanMode::Exact;
    }
}

void MainWindow::updateInputBoxState() {
    core::ScanMode mode = currentScanMode();
    if (mode == core::ScanMode::UnknownInitial) {
        valueEdit_->setEnabled(false);
        valueEdit2_->setEnabled(false);
    } else if (mode == core::ScanMode::Between) {
        valueEdit_->setEnabled(true);
        valueEdit2_->setEnabled(true);
    } else {
        valueEdit_->setEnabled(true);
        valueEdit2_->setEnabled(false);
    }
    if (mode == core::ScanMode::Aob || currentValueType() == core::ValueType::ArrayOfByte) {
        valueEdit_->setPlaceholderText("e.g. 90 90 ?? FF");
    } else {
        valueEdit_->setPlaceholderText("");
    }
}

core::ScanParams MainWindow::currentScanParams(bool /*forNext*/) const {
    core::ScanParams p;
    p.type = currentValueType();
    p.mode = currentScanMode();
    p.value1 = valueEdit_->text().toStdString();
    p.value2 = valueEdit2_->text().toStdString();
    p.requireWritable = writableCheck_ && writableCheck_->isChecked();
    p.requireExecutable = executableCheck_ && executableCheck_->isChecked();
    p.skipMaskedRegions = !skipMaskedCheck_ || skipMaskedCheck_->isChecked();
    p.hexInput = hexCheck_ && hexCheck_->isChecked();
    bool ok = false;
    unsigned long long align = alignmentEdit_->text().toULongLong(&ok, 0);
    if (ok && align > 0) p.alignment = static_cast<size_t>(align);
    auto defaultAlign = [](core::ValueType t) -> size_t {
        switch (t) {
            case core::ValueType::Byte: return 1;
            case core::ValueType::Int16: return 2;
            case core::ValueType::Int32: return 4;
            case core::ValueType::Int64: return 8;
            case core::ValueType::Float: return 4;
            case core::ValueType::Double: return 8;
            default: return 1;
        }
    };
    if (fastScanCheck_ && fastScanCheck_->isChecked() && p.alignment == 0) {
        p.alignment = defaultAlign(p.type);
    }
    unsigned long long start = startAddrEdit_->text().toULongLong(&ok, 0);
    if (ok) p.startAddress = static_cast<uintptr_t>(start);
    unsigned long long end = endAddrEdit_->text().toULongLong(&ok, 0);
    if (ok) p.endAddress = static_cast<uintptr_t>(end);

    const_cast<MainWindow*>(this)->updateInputBoxState();
    return p;
}

void MainWindow::onDetach() {
    if (scanner_) {
        scanner_->requestCancel();
    }
    for (size_t i = 0; i < watches_.size(); ++i) {
        if (watches_[i].isScript && watches_[i].scriptActive) {
            setScriptState(i, false);
        }
    }
    if (target_) {
        target_->detach();
        target_.reset();
        scanner_.reset();
        injector_.reset();
    }
    freezeTimer_->stop();
    watchRefreshTimer_->stop();
    watches_.clear();
    watchTable_->setRowCount(0);
    lastValues_.clear();
    firstValues_.clear();
    liveValues_.clear();
    changedAddresses_.clear();
    if (pointerScene_) pointerScene_->clear();
    if (memoryScene_) memoryScene_->clear();
    notifyResultsReset();
    resetScanHistory();
    updateStatus("No process");
    setStatusDetail(QString());
    updateResultsCount();
    cachedRegions_.clear();
    metaScores_.clear();
    guessedTypes_.clear();
    metaGroups_.clear();
    pointerCandidates_.clear();
    updateAttachUi();
}

void MainWindow::onFirstScan() {
    if (!scanner_ || scanInProgress_) return;
    resultDisplayType_ = currentValueType();
    resetScanHistory();
    auto params = currentScanParams(false);
    scanInProgress_ = true;
    updateUndoState();
    setStatusDetail(QStringLiteral("Scanning memory..."));
    size_t totalBytes = scanner_->estimateWork(params);
    scanProgress_->setRange(totalBytes > 0 ? 0 : 0, totalBytes > 0 ? 100 : 0);
    scanProgress_->setVisible(true);
    auto *progressDone = new std::atomic<size_t>(0);
    auto *worker = new ScanWorker(scanner_.get(), params, ScanWorker::Kind::First, progressDone, totalBytes);
    scanner_->resetCancel();
    firstScanBtn_->setEnabled(false);
    nextScanBtn_->setEnabled(false);
    refreshValuesBtn_->setEnabled(false);
    autoRefreshCheck_->setEnabled(false);
    stopScanBtn_->setEnabled(true);
    if (totalBytes > 0) {
        scanProgressTimer_->start();
        connect(scanProgressTimer_, &QTimer::timeout, this, [this, progressDone, totalBytes]() {
            size_t done = progressDone->load(std::memory_order_relaxed);
            int pct = static_cast<int>((std::min(done, totalBytes) * 100) / totalBytes);
            scanProgress_->setValue(pct);
        });
    } else {
        scanProgressTimer_->stop();
    }
    scanThread_ = QThread::create([worker]() {
        worker->run();
    });
    connect(scanThread_, &QThread::finished, this, [this, worker]() {
        bool ok = worker->success;
        auto *progress = worker->progressDone_;
        delete worker;
        scanThread_->deleteLater();
        scanThread_ = nullptr;
        scanInProgress_ = false;
        scanProgress_->setVisible(false);
        scanProgressTimer_->stop();
        firstScanBtn_->setEnabled(true);
        nextScanBtn_->setEnabled(true);
        refreshValuesBtn_->setEnabled(true);
        autoRefreshCheck_->setEnabled(true);
        stopScanBtn_->setEnabled(false);
        
        // Ensure input boxes are enabled if mode requires them
        updateInputBoxState();
        
        updateUndoState();
        delete progress;
        if (!ok) {
            QMessageBox::warning(this, "Scan failed", "Could not parse value, read memory, or scan was cancelled");
            setStatusDetail(QStringLiteral("Scan failed"));
            return;
        }
        lastValues_.clear();
        firstValues_.clear();
        liveValues_.clear();
        populateResults();
        recordScanSnapshot();
        size_t count = scanner_ ? scanner_->results().size() : 0;
        if (count == 0 && scanner_ && scanner_->hasShadowCopy()) {
            setStatusDetail(QStringLiteral("Snapshot complete. Perform Next Scan."));
        } else {
            QString detail = QString("%1 result%2").arg(static_cast<qulonglong>(count)).arg(count == 1 ? "" : "s");
            setStatusDetail(detail);
        }
    });
    scanThread_->start();
}

void MainWindow::onNextScan() {
    if (!scanner_ || scanInProgress_) return;
    auto params = currentScanParams(true);
    scanInProgress_ = true;
    updateUndoState();
    setStatusDetail(QStringLiteral("Filtering results..."));
    size_t perValue = 0;
    switch (params.type) {
        case core::ValueType::Byte: perValue = sizeof(int8_t); break;
        case core::ValueType::Int16: perValue = sizeof(int16_t); break;
        case core::ValueType::Int32: perValue = sizeof(int32_t); break;
        case core::ValueType::Int64: perValue = sizeof(int64_t); break;
        case core::ValueType::Float: perValue = sizeof(float); break;
        case core::ValueType::Double: perValue = sizeof(double); break;
        case core::ValueType::ArrayOfByte:
        case core::ValueType::String:
            perValue = 1;
            break;
    }
    size_t totalBytes = perValue * scanner_->results().size();
    scanProgress_->setRange(totalBytes > 0 ? 0 : 0, totalBytes > 0 ? 100 : 0);
    scanProgress_->setVisible(true);
    auto *progressDone = new std::atomic<size_t>(0);
    auto *worker = new ScanWorker(scanner_.get(), params, ScanWorker::Kind::Next, progressDone, totalBytes);
    scanner_->resetCancel();
    firstScanBtn_->setEnabled(false);
    nextScanBtn_->setEnabled(false);
    refreshValuesBtn_->setEnabled(false);
    autoRefreshCheck_->setEnabled(false);
    stopScanBtn_->setEnabled(true);
    if (totalBytes > 0) {
        scanProgressTimer_->start();
        connect(scanProgressTimer_, &QTimer::timeout, this, [this, progressDone, totalBytes]() {
            size_t done = progressDone->load(std::memory_order_relaxed);
            int pct = static_cast<int>((std::min(done, totalBytes) * 100) / totalBytes);
            scanProgress_->setValue(pct);
        });
    } else {
        scanProgressTimer_->stop();
    }
    scanThread_ = QThread::create([worker]() {
        worker->run();
    });
    connect(scanThread_, &QThread::finished, this, [this, worker]() {
        bool ok = worker->success;
        auto *progress = worker->progressDone_;
        delete worker;
        scanThread_->deleteLater();
        scanThread_ = nullptr;
        scanInProgress_ = false;
        scanProgress_->setVisible(false);
        scanProgressTimer_->stop();
        firstScanBtn_->setEnabled(true);
        nextScanBtn_->setEnabled(true);
        refreshValuesBtn_->setEnabled(true);
        autoRefreshCheck_->setEnabled(true);
        stopScanBtn_->setEnabled(false);
        
        // Ensure input boxes are enabled if mode requires them
        updateInputBoxState();
        
        updateUndoState();
        delete progress;
        if (!ok) {
            QMessageBox::warning(this, "Scan failed", "Could not parse value, read memory, or scan was cancelled");
            setStatusDetail(QStringLiteral("Scan failed"));
            return;
        }
        populateResults();
        recordScanSnapshot();
        size_t count = scanner_ ? scanner_->results().size() : 0;
        QString detail = QString("%1 result%2").arg(static_cast<qulonglong>(count)).arg(count == 1 ? "" : "s");
        setStatusDetail(detail);
    });
    scanThread_->start();
}

void MainWindow::onUndoScan() {
    if (!scanner_ || scanInProgress_) return;
    if (scanHistory_.size() <= 1) return;
    scanHistory_.pop_back();
    scanner_->restoreResults(scanHistory_.back());
    populateResults();
    updateUndoState();
}

void MainWindow::onProcessClicked() {
    if (!processDialog_) {
        processDialog_ = new ProcessDialog(this);
        connect(processDialog_, &ProcessDialog::processChosen, this,
                [this](pid_t pid, const QString &name) {
                    freezeTimer_->stop();
                    for (size_t i = 0; i < watches_.size(); ++i) {
                        if (watches_[i].isScript && watches_[i].scriptActive) {
                            setScriptState(i, false);
                        }
                    }
                    watches_.clear();
                    watchTable_->setRowCount(0);
                    lastValues_.clear();
                    firstValues_.clear();
                    liveValues_.clear();
                    changedAddresses_.clear();
                    notifyResultsReset();
                    resetScanHistory();
                    target_ = std::make_unique<core::TargetProcess>();
                    if (!target_->attach(pid)) {
                        QString msg = QString::fromStdString(target_->lastError());
                        msg += ptraceHint();
                        QMessageBox::warning(this, "Attach failed", msg);
                        target_.reset();
                        updateStatus("No process");
                        setStatusDetail(QString());
                        return;
                    }
                    scanner_ = std::make_unique<core::MemoryScanner>(*target_);
                    injector_ = std::make_unique<core::CodeInjector>(*target_);
                    cachedRegions_ = target_->regions();
                    updateStatus(QString("Attached to %1 (%2)").arg(name).arg(pid));
                    setStatusDetail(QString());
                    updateAttachUi();
                    if (autoRefreshCheck_->isChecked()) {
                        watchRefreshTimer_->start(refreshIntervalSpin_->value());
                    }
                });
    }
    processDialog_->show();
    processDialog_->raise();
    processDialog_->activateWindow();
}

int MainWindow::resultRowCount() const {
    if (!scanner_) return 0;
    return std::min<int>(static_cast<int>(scanner_->results().size()), 10000);
}

void MainWindow::populateResults() {
    if (!scanner_) {
        lastValues_.clear();
        liveValues_.clear();
        firstValues_.clear();
        changedAddresses_.clear();
        notifyResultsReset();
        return;
    }
    
    const auto &res = scanner_->results();
    
    lastValues_.clear();
    liveValues_.clear();
    if (res.size() > 100000) {
        firstValues_.clear();
    }

    if (!res.empty()) {
        updateGlobalAddress(res.front().address, resultDisplayType_, QStringLiteral("Scan result"));
    }
    
    analyzeMetaResults();
    notifyResultsReset();
}

void MainWindow::populateWatchList(bool force) {
    if (!target_) {
        watchTable_->setRowCount(0);
        return;
    }
    if (static_cast<size_t>(watchTable_->rowCount()) != watches_.size()) {
        watchTable_->setRowCount(static_cast<int>(watches_.size()));
        force = true;
    }
    for (int i = 0; i < static_cast<int>(watches_.size()); ++i) {
        auto &w = watches_[i];
        QTableWidgetItem *freezeItem = watchTable_->item(i, 0);
        if (!freezeItem) {
            freezeItem = new QTableWidgetItem;
            watchTable_->setItem(i, 0, freezeItem);
        }
        if (w.isScript) {
            freezeItem->setFlags(freezeItem->flags() & ~Qt::ItemIsUserCheckable);
            freezeItem->setText(w.scriptActive ? "ON" : "");
        } else {
            freezeItem->setFlags(freezeItem->flags() | Qt::ItemIsUserCheckable);
            freezeItem->setText(QString());
            freezeItem->setCheckState(w.frozen ? Qt::Checked : Qt::Unchecked);
        }
        QTableWidgetItem *descItem = watchTable_->item(i, 1);
        if (!descItem) {
            descItem = new QTableWidgetItem;
            watchTable_->setItem(i, 1, descItem);
        }
        descItem->setText(w.description);

        QTableWidgetItem *addrItem = watchTable_->item(i, 2);
        if (!addrItem) {
            addrItem = new QTableWidgetItem;
            watchTable_->setItem(i, 2, addrItem);
        }
        addrItem->setText(w.isScript
                              ? QStringLiteral("<script>")
                              : QString::asprintf("0x%llx", static_cast<unsigned long long>(w.address)));

        QTableWidgetItem *typeItem = watchTable_->item(i, 3);
        if (!typeItem) {
            typeItem = new QTableWidgetItem;
            watchTable_->setItem(i, 3, typeItem);
        }
        typeItem->setText(w.isScript ? QStringLiteral("Script") : typeToString(w.type));

        QTableWidgetItem *valItem = watchTable_->item(i, 4);
        if (!valItem) {
            valItem = new QTableWidgetItem;
            watchTable_->setItem(i, 4, valItem);
        }
        if (w.isScript) {
            valItem->setText(w.scriptActive ? "Enabled" : "Disabled");
            valItem->setBackground(w.scriptActive ? QBrush(QColor("#2f6fed")) : QBrush(Qt::NoBrush));
        } else if (force) {
            valItem->setText(formatValue(w.last.isEmpty() ? w.stored : w.last, w.type));
            valItem->setBackground(Qt::NoBrush);
        }

        QTableWidgetItem *ptrItem = watchTable_->item(i, 5);
        if (!ptrItem) {
            ptrItem = new QTableWidgetItem;
            watchTable_->setItem(i, 5, ptrItem);
        }
        ptrItem->setText(w.isScript ? "Script" : (w.isPointer ? "Yes" : ""));
    }
    refreshWatchValues(force);
}

void MainWindow::refreshWatchValues(bool force) {
    if (!target_ || !target_->isAttached()) return;
    if (watchValueEditing_ && !force) return;
    if (static_cast<size_t>(watchTable_->rowCount()) != watches_.size()) {
        populateWatchList(true);
        return;
    }
    for (int i = 0; i < static_cast<int>(watches_.size()); ++i) {
        auto &w = watches_[i];
        if (w.isScript) continue;
        
        uintptr_t effectiveAddr = w.address;
        if (w.isPointer && !w.offsets.empty()) {
            effectiveAddr = resolvePointerChain(w.address, w.offsets);
        }

        if (effectiveAddr == 0) {
            auto *valItem = watchTable_->item(i, 4);
            if (valItem) valItem->setText("??");
            continue;
        }

        QByteArray current;
        bool ok = true;
        switch (w.type) {
            case core::ValueType::Byte: {
                int8_t v = 0; ok = target_->readMemory(effectiveAddr, &v, sizeof(v)); if (ok) current = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
            }
            case core::ValueType::Int16: {
                int16_t v = 0; ok = target_->readMemory(effectiveAddr, &v, sizeof(v)); if (ok) current = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
            }
            case core::ValueType::Int32: {
                int32_t v = 0; ok = target_->readMemory(effectiveAddr, &v, sizeof(v)); if (ok) current = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
            }
            case core::ValueType::Int64: {
                int64_t v = 0; ok = target_->readMemory(effectiveAddr, &v, sizeof(v)); if (ok) current = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
            }
            case core::ValueType::Float: {
                float v = 0; ok = target_->readMemory(effectiveAddr, &v, sizeof(v)); if (ok) current = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
            }
            case core::ValueType::Double: {
                double v = 0; ok = target_->readMemory(effectiveAddr, &v, sizeof(v)); if (ok) current = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
            }
            case core::ValueType::ArrayOfByte:
            case core::ValueType::String:
                ok = false;
                break;
        }
        auto *valItem = watchTable_->item(i, 4);
        if (!ok) {
            if (valItem) {
                valItem->setText("??");
                pulseWatchRow(i, QColor("#ff4d4d"));
            }
            continue;
        }
        w.prev = w.last;
        w.last = current;
        if (!w.frozen) {
            w.stored = current;
        }
        if (valItem) {
            valItem->setText(formatValue(current, w.type));
            if (!w.prev.isEmpty() && w.prev != current) {
                bool prevOk = false;
                bool nowOk = false;
                double prevVal = decodeNumeric(w.prev, w.type, &prevOk);
                double nowVal = decodeNumeric(current, w.type, &nowOk);
                double diff = (prevOk && nowOk) ? std::abs(nowVal - prevVal) : 0.0;
                double threshold = (w.type == core::ValueType::Float || w.type == core::ValueType::Double) ? 0.5 : 5.0;
                QColor pulseColor = diff > threshold ? QColor("#ff7e5f") : QColor("#45ffaf");
                pulseWatchRow(i, pulseColor);
            }
        }
    }
    refreshMemoryVisualization();
}

void MainWindow::onModifyValue() {
    if (!target_) return;
    auto idx = watchTable_->currentIndex();
    if (!idx.isValid()) return;
    int row = idx.row();
    if (row < 0 || row >= static_cast<int>(watches_.size())) return;
    auto &w = watches_[row];
    uintptr_t addr = w.address;
    auto type = w.type;
    bool ok = false;
    QByteArray bytes;
    switch (type) {
        case core::ValueType::Byte: {
            int v = newValueEdit_->text().toInt(&ok);
            if (!ok) break;
            int8_t vv = static_cast<int8_t>(v);
            target_->writeMemory(addr, &vv, sizeof(vv));
            bytes = QByteArray(reinterpret_cast<char *>(&vv), sizeof(vv));
            break;
        }
        case core::ValueType::Int16: {
            int v = newValueEdit_->text().toInt(&ok);
            if (!ok) break;
            int16_t vv = static_cast<int16_t>(v);
            target_->writeMemory(addr, &vv, sizeof(vv));
            bytes = QByteArray(reinterpret_cast<char *>(&vv), sizeof(vv));
            break;
        }
        case core::ValueType::Int32: {
            int32_t v = newValueEdit_->text().toInt(&ok);
            if (!ok) break;
            target_->writeMemory(addr, &v, sizeof(v));
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
        case core::ValueType::Int64: {
            int64_t v = newValueEdit_->text().toLongLong(&ok);
            if (!ok) break;
            target_->writeMemory(addr, &v, sizeof(v));
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
        case core::ValueType::Float: {
            float v = newValueEdit_->text().toFloat(&ok);
            if (!ok) break;
            target_->writeMemory(addr, &v, sizeof(v));
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
        case core::ValueType::Double: {
            double v = newValueEdit_->text().toDouble(&ok);
            if (!ok) break;
            target_->writeMemory(addr, &v, sizeof(v));
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
    }
    if (!bytes.isEmpty()) {
        w.stored = bytes;
        w.last = bytes;
        if (freezeCheck_->isChecked()) {
            w.frozen = true;
            if (!freezeTimer_->isActive()) freezeTimer_->start();
        }
        populateWatchList(true);
    }
}

void MainWindow::onAddWatch() {
    if (!target_ || !scanner_) return;
    auto selection = resultsTable_->selectionModel()->selectedRows();
    if (selection.isEmpty()) {
        QMessageBox::information(this, "Add to cheat table", "No scan result selected.");
        return;
    }
    for (const auto &idx : selection) {
        auto sourceIdx = resultsProxy_->mapToSource(idx);
        int row = sourceIdx.row();
        if (row < 0 || row >= static_cast<int>(scanner_->results().size())) continue;
        uintptr_t addr = scanner_->results()[row].address;
        WatchEntry w;
        w.address = addr;
        w.type = currentValueType();
        w.description.clear();
        w.isPointer = false;
        w.frozen = false;
        w.stored.clear();
        QByteArray cur;
        switch (w.type) {
            case core::ValueType::Byte: { int8_t v=0; if (target_->readMemory(addr,&v,sizeof(v))) cur=QByteArray(reinterpret_cast<char*>(&v),sizeof(v)); break; }
            case core::ValueType::Int16:{ int16_t v=0; if (target_->readMemory(addr,&v,sizeof(v))) cur=QByteArray(reinterpret_cast<char*>(&v),sizeof(v)); break; }
            case core::ValueType::Int32:{ int32_t v=0; if (target_->readMemory(addr,&v,sizeof(v))) cur=QByteArray(reinterpret_cast<char*>(&v),sizeof(v)); break; }
            case core::ValueType::Int64:{ int64_t v=0; if (target_->readMemory(addr,&v,sizeof(v))) cur=QByteArray(reinterpret_cast<char*>(&v),sizeof(v)); break; }
            case core::ValueType::Float:{ float v=0; if (target_->readMemory(addr,&v,sizeof(v))) cur=QByteArray(reinterpret_cast<char*>(&v),sizeof(v)); break; }
            case core::ValueType::Double:{ double v=0; if (target_->readMemory(addr,&v,sizeof(v))) cur=QByteArray(reinterpret_cast<char*>(&v),sizeof(v)); break; }
            case core::ValueType::ArrayOfByte:
            case core::ValueType::String:
                break;
        }
        w.last = cur;
        if (!w.frozen) w.stored = cur;
        watches_.push_back(w);
    }
    if (!watches_.empty() && !freezeTimer_->isActive()) {
        freezeTimer_->start();
    }
    if (!watches_.empty() && !watchRefreshTimer_->isActive()) {
        watchRefreshTimer_->start();
    }
    populateWatchList(true);
}

void MainWindow::onRemoveWatch() {
    auto idx = watchTable_->currentIndex();
    if (!idx.isValid()) return;
    int row = idx.row();
    if (row >= 0 && row < static_cast<int>(watches_.size())) {
        if (watches_[row].isScript && watches_[row].scriptActive) {
            setScriptState(static_cast<size_t>(row), false);
        }
        watches_.erase(watches_.begin() + row);
        populateWatchList(true);
    }
}

void MainWindow::onUpdateWatchValue() {
    if (!target_) return;
    auto idx = watchTable_->currentIndex();
    if (!idx.isValid()) return;
    int row = idx.row();
    if (row < 0 || row >= static_cast<int>(watches_.size())) return;
    bool ok = false;
    auto &w = watches_[row];
    if (w.isScript) return;
    QByteArray bytes;
    switch (w.type) {
        case core::ValueType::Byte: {
            int v = watchValueEdit_->text().toInt(&ok);
            if (!ok) return;
            int8_t vv = static_cast<int8_t>(v);
            bytes = QByteArray(reinterpret_cast<char *>(&vv), sizeof(vv));
            break;
        }
        case core::ValueType::Int16: {
            int v = watchValueEdit_->text().toInt(&ok);
            if (!ok) return;
            int16_t vv = static_cast<int16_t>(v);
            bytes = QByteArray(reinterpret_cast<char *>(&vv), sizeof(vv));
            break;
        }
        case core::ValueType::Int32: {
            int32_t v = watchValueEdit_->text().toInt(&ok);
            if (!ok) return;
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
        case core::ValueType::Int64: {
            int64_t v = watchValueEdit_->text().toLongLong(&ok);
            if (!ok) return;
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
        case core::ValueType::Float: {
            float v = watchValueEdit_->text().toFloat(&ok);
            if (!ok) return;
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
        case core::ValueType::Double: {
            double v = watchValueEdit_->text().toDouble(&ok);
            if (!ok) return;
            bytes = QByteArray(reinterpret_cast<char *>(&v), sizeof(v));
            break;
        }
    }
    if (bytes.isEmpty()) return;
    if (!target_->writeMemory(w.address, bytes.data(), static_cast<size_t>(bytes.size()))) {
        QMessageBox::warning(this, "Write failed", "Could not write value to target process.");
        return;
    }
    w.prev = w.last;
    w.last = bytes;
    w.stored = bytes;
    if (freezeCheck_->isChecked()) {
        w.frozen = true;
        if (!freezeTimer_->isActive()) freezeTimer_->start();
    }
    populateWatchList(true);
}

void MainWindow::onSaveTable() {
    if (watches_.empty()) return;
    QString fileName = QFileDialog::getSaveFileName(this, "Save Cheat Table", QString(), "Cheat Tables (*.json);;All Files (*.*)");
    if (fileName.isEmpty()) return;
    QJsonArray arr;
    for (const auto &w : watches_) {
        QJsonObject o;
        if (w.isScript) {
            o["isScript"] = true;
            o["description"] = w.description;
            o["script"] = w.scriptSource;
            o["active"] = w.scriptActive;
        } else {
            o["address"] = QString::asprintf("0x%llx", static_cast<unsigned long long>(w.address));
            o["type"] = typeToString(w.type);
            o["description"] = w.description;
            o["pointer"] = w.isPointer;
            o["frozen"] = w.frozen;
            QString valueHex;
            for (int i = 0; i < w.stored.size(); ++i) {
                uint8_t b = static_cast<uint8_t>(w.stored[static_cast<int>(i)]);
                valueHex += QString::asprintf("%02x", b);
                if (i + 1 < w.stored.size()) valueHex += " ";
            }
            o["valueBytes"] = valueHex;
        }
        arr.append(o);
    }
    QJsonObject root;
    root["entries"] = arr;
    QJsonDocument doc(root);
    QFile f(fileName);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(doc.toJson());
    }
}

void MainWindow::onLoadTable() {
    QString fileName = QFileDialog::getOpenFileName(this, "Load Cheat Table", QString(), "Cheat Tables (*.json);;All Files (*.*)");
    if (fileName.isEmpty()) return;
    QFile f(fileName);
    if (!f.open(QIODevice::ReadOnly)) return;
    QByteArray data = f.readAll();
    QJsonParseError err{};
    QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return;
    QJsonObject root = doc.object();
    QJsonArray arr = root["entries"].toArray();
    watches_.clear();
    for (const auto &val : arr) {
        if (!val.isObject()) continue;
        QJsonObject o = val.toObject();
        if (o["isScript"].toBool()) {
            WatchEntry w;
            w.isScript = true;
            w.description = o["description"].toString();
            w.scriptSource = o["script"].toString();
            w.scriptActive = false;
            watches_.push_back(w);
            continue;
        }
        QString addrStr = o["address"].toString();
        bool ok = false;
        uintptr_t addr = addrStr.toULongLong(&ok, 0);
        if (!ok || addr == 0) continue;
        QString typeStr = o["type"].toString();
        core::ValueType type = core::ValueType::Int32;
        if (typeStr == "Byte") type = core::ValueType::Byte;
        else if (typeStr == "2 Bytes") type = core::ValueType::Int16;
        else if (typeStr == "4 Bytes") type = core::ValueType::Int32;
        else if (typeStr == "8 Bytes") type = core::ValueType::Int64;
        else if (typeStr == "Float") type = core::ValueType::Float;
        else if (typeStr == "Double") type = core::ValueType::Double;
        else if (typeStr == "AOB") type = core::ValueType::ArrayOfByte;
        else if (typeStr == "String") type = core::ValueType::String;
        WatchEntry w;
        w.address = addr;
        w.type = type;
        w.description = o["description"].toString();
        w.isPointer = o["pointer"].toBool(false);
        w.frozen = o["frozen"].toBool(false);
        QString valueHex = o["valueBytes"].toString();
        QByteArray stored;
        std::istringstream iss(valueHex.toStdString());
        std::string tok;
        while (iss >> tok) {
            uint8_t b = static_cast<uint8_t>(std::stoul(tok, nullptr, 16));
            stored.append(static_cast<char>(b));
        }
        w.stored = stored;
        w.last = stored;
        watches_.push_back(w);
    }
    bool anyFrozen = false;
    for (const auto &w : watches_) {
        if (w.frozen) { anyFrozen = true; break; }
    }
    if (anyFrozen && !freezeTimer_->isActive()) freezeTimer_->start();
    if (!watches_.empty() && !watchRefreshTimer_->isActive()) watchRefreshTimer_->start();
    populateWatchList(true);
}

QString MainWindow::hexDump(uintptr_t address, size_t length) const {
    if (!target_ || length == 0 || length > 4096) {
        return {};
    }
    std::vector<uint8_t> buf(length);
    if (!target_->readMemory(address, buf.data(), length)) {
        return "Failed to read memory";
    }
    QString out;
    const size_t bytesPerLine = 16;
    for (size_t i = 0; i < length; i += bytesPerLine) {
        out += QString::asprintf("%016llx  ", static_cast<unsigned long long>(address + i));
        QString hexPart;
        QString asciiPart;
        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < length) {
                uint8_t b = buf[i + j];
                hexPart += QString::asprintf("%02x ", b);
                asciiPart += (b >= 32 && b <= 126) ? QChar(b) : '.';
            } else {
                hexPart += "   ";
                asciiPart += ' ';
            }
        }
        out += hexPart;
        out += " ";
        out += asciiPart;
        out += "\n";
    }
    return out;
}

void MainWindow::onViewMemory() {
    if (!memoryViewer_) return;
    if (!target_ || !target_->isAttached()) {
        QMessageBox::warning(this, "Memory Viewer", "Attach to a process before opening memory view.");
        return;
    }
    uintptr_t baseAddr = 0;
    auto cheatIdx = watchTable_->currentIndex();
    if (cheatIdx.isValid()) {
        int row = cheatIdx.row();
        if (row >= 0 && row < static_cast<int>(watches_.size()) && !watches_[row].isScript) {
            baseAddr = watches_[row].address;
        }
    }
    if (baseAddr == 0) {
        auto resIdx = resultsTable_->currentIndex();
        if (resIdx.isValid() && scanner_) {
            auto sourceIdx = resultsProxy_->mapToSource(resIdx);
            int row = sourceIdx.row();
            if (row >= 0 && row < static_cast<int>(scanner_->results().size())) {
                baseAddr = scanner_->results()[row].address;
            }
        }
    }
    if (baseAddr == 0 && scanner_ && !scanner_->results().empty()) {
        baseAddr = scanner_->results().front().address;
    }
    if (baseAddr == 0 && globalAddress_ != 0) {
        baseAddr = globalAddress_;
    }
    if (baseAddr == 0) {
        QMessageBox::information(this, "Memory Viewer",
                                 "Select an address from the scan results or watch list first.");
        return;
    }
    memoryViewer_->setTarget(target_.get(), baseAddr);
    if (memoryViewerDock_) {
        memoryViewerDock_->show();
        memoryViewerDock_->raise();
        memoryViewerDock_->activateWindow();
        if (auto *widget = memoryViewerDock_->widget()) {
            widget->setFocus(Qt::OtherFocusReason);
        }
    }
}

void MainWindow::refreshResultValues() {
    if (!target_ || !target_->isAttached() || !scanner_ || !resultsProxy_) return;
    const int proxyCount = resultsProxy_->rowCount();
    if (proxyCount <= 0) return;

    auto topIdx = resultsTable_->indexAt(QPoint(0, 0));
    int firstProxy = topIdx.isValid() ? topIdx.row() : 0;
    auto bottomIdx = resultsTable_->indexAt(QPoint(0, resultsTable_->viewport()->height() - 1));
    int lastProxy = bottomIdx.isValid() ? bottomIdx.row() : proxyCount - 1;
    if (firstProxy > lastProxy) std::swap(firstProxy, lastProxy);

    std::vector<int> sourceRows;
    auto appendProxyRow = [&](int proxyRow) {
        if (proxyRow < 0 || proxyRow >= resultsProxy_->rowCount()) return;
        auto srcIdx = resultsProxy_->mapToSource(resultsProxy_->index(proxyRow, 0));
        if (!srcIdx.isValid()) return;
        sourceRows.push_back(srcIdx.row());
    };
    for (int proxyRow = firstProxy; proxyRow <= lastProxy; ++proxyRow) appendProxyRow(proxyRow);
    if (auto *sel = resultsTable_->selectionModel()) {
        for (const auto &idx : sel->selectedRows()) appendProxyRow(idx.row());
    }
    if (sourceRows.empty()) appendProxyRow(0);
    std::sort(sourceRows.begin(), sourceRows.end());
    sourceRows.erase(std::unique(sourceRows.begin(), sourceRows.end()), sourceRows.end());

    auto type = resultDisplayType_;
    changedAddresses_.clear();
    spikedAddresses_.clear();
    std::vector<int> changedRows;
    auto spikeThreshold = [](core::ValueType t) {
        switch (t) {
            case core::ValueType::Float: return 0.5;
            case core::ValueType::Double: return 1.0;
            default: return 10.0;
        }
    };

    for (int row : sourceRows) {
        uintptr_t addr = resultAddressForRow(row);
        if (addr == 0) continue;
        uint64_t previous = 0;
        bool hasPrevious = false;
        if (auto it = liveValues_.find(addr); it != liveValues_.end()) {
            previous = it->second;
            hasPrevious = true;
        }
        uint64_t raw = previous;
        bool readOk = false;
        switch (type) {
            case core::ValueType::Byte: {
                int8_t v = 0;
                if (target_->readMemory(addr, &v, sizeof(v))) {
                    std::memcpy(&raw, &v, sizeof(v));
                    readOk = true;
                }
                break;
            }
            case core::ValueType::Int16: {
                int16_t v = 0;
                if (target_->readMemory(addr, &v, sizeof(v))) {
                    std::memcpy(&raw, &v, sizeof(v));
                    readOk = true;
                }
                break;
            }
            case core::ValueType::Int32: {
                int32_t v = 0;
                if (target_->readMemory(addr, &v, sizeof(v))) {
                    std::memcpy(&raw, &v, sizeof(v));
                    readOk = true;
                }
                break;
            }
            case core::ValueType::Int64: {
                int64_t v = 0;
                if (target_->readMemory(addr, &v, sizeof(v))) {
                    std::memcpy(&raw, &v, sizeof(v));
                    readOk = true;
                }
                break;
            }
            case core::ValueType::Float: {
                float v = 0;
                if (target_->readMemory(addr, &v, sizeof(v))) {
                    std::memcpy(&raw, &v, sizeof(v));
                    readOk = true;
                }
                break;
            }
            case core::ValueType::Double: {
                double v = 0;
                if (target_->readMemory(addr, &v, sizeof(v))) {
                    std::memcpy(&raw, &v, sizeof(v));
                    readOk = true;
                }
                break;
            }
            case core::ValueType::ArrayOfByte:
            case core::ValueType::String:
                continue;
        }

        if (!readOk) continue;
        liveValues_[addr] = raw;
        if (hasPrevious && raw != previous) {
            changedAddresses_.insert(addr);
            bool prevOk = false;
            bool nowOk = false;
            double prevVal = decodeRaw(previous, type, &prevOk);
            double nowVal = decodeRaw(raw, type, &nowOk);
            if (prevOk && nowOk && std::abs(nowVal - prevVal) >= spikeThreshold(type)) {
                spikedAddresses_.insert(addr);
                showSpark(addr);
            }
            changedRows.push_back(row);
        }
    }

    if (resultsModel_ && !changedRows.empty()) {
        std::sort(changedRows.begin(), changedRows.end());
        changedRows.erase(std::unique(changedRows.begin(), changedRows.end()), changedRows.end());
        resultsModel_->notifyRowsChanged(changedRows);
    }
    updateTrackedEntries();
    updateResultsCount();
}

void MainWindow::setResultDisplayType(core::ValueType type) {
    if (resultDisplayType_ == type) return;
    resultDisplayType_ = type;
    analyzeMetaResults();
    notifyResultsReset();
}

void MainWindow::updateResultColumnVisibility() {
    if (!resultsTable_) return;
    resultsTable_->setColumnHidden(2, !showPreviousColumn_);
}

uintptr_t MainWindow::resultAddressForRow(int row) const {
    if (!scanner_) return 0;
    const auto &res = scanner_->results();
    if (row < 0 || row >= static_cast<int>(res.size())) return 0;
    return res[row].address;
}

uintptr_t MainWindow::resolvePointerChain(uintptr_t base, const std::vector<int64_t> &offsets) const {
    if (!target_ || !target_->isAttached()) return 0;
    uintptr_t current = base;
    for (size_t i = 0; i < offsets.size(); ++i) {
        uintptr_t pointed = 0;
        if (!target_->readMemory(current, &pointed, sizeof(pointed))) return 0;
        current = pointed + offsets[i];
    }
    return current;
}

QVariant MainWindow::resultData(int row, int column, int role) const {
    if (!scanner_) return QVariant();
    const auto &res = scanner_->results();
    if (row < 0 || row >= static_cast<int>(res.size())) return QVariant();
    uintptr_t addr = res[row].address;
    uint64_t currentRaw = res[row].raw;
    if (auto it = liveValues_.find(addr); it != liveValues_.end()) {
        currentRaw = it->second;
    }
    if (role == Qt::DisplayRole) {
        switch (column) {
            case 0:
                return QString::asprintf("0x%llx", static_cast<unsigned long long>(addr));
            case 1:
                return formatRawValue(currentRaw, resultDisplayType_);
            case 2: {
                auto it = lastValues_.find(addr);
                if (it != lastValues_.end()) {
                    return formatRawValue(it->second, resultDisplayType_);
                }
                return QString();
            }
            case 3: {
                uint64_t firstRaw = currentRaw;
                if (auto it = firstValues_.find(addr); it != firstValues_.end()) {
                    firstRaw = it->second;
                }
                return formatRawValue(firstRaw, resultDisplayType_);
            }
            case 4:
                return typeToString(resultDisplayType_);
        }
    }
    if (role == Qt::BackgroundRole && column == 1) {
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (auto it = sparkTimes_.find(addr); it != sparkTimes_.end()) {
            if (now - it->second <= sparkWindowMs_) {
                return QBrush(QColor("#8447ff"));
            }
        }
        if (spikedAddresses_.find(addr) != spikedAddresses_.end()) {
            return QBrush(QColor("#ffb347"));
        }
        if (changedAddresses_.find(addr) != changedAddresses_.end()) {
            return QBrush(QColor("#2dd7aa"));
        }
    }
    if (role == Qt::ToolTipRole) {
        return metaSummary(addr);
    }
    if (role == Qt::UserRole) {
        if (auto it = metaScores_.find(addr); it != metaScores_.end()) return it->second;
        return 0.0;
    }
    return QVariant();
}

void MainWindow::notifyResultsReset() {
    if (resultsModel_) resultsModel_->resetModel();
    if (resultsProxy_) resultsProxy_->invalidate();
    updateResultColumnVisibility();
    updateResultsCount();
}

void MainWindow::updateGlobalAddress(uintptr_t address, core::ValueType typeHint, const QString &source) {
    if (address == 0) return;
    globalAddress_ = address;
    lastSmartType_ = typeHint;
    lastSmartSource_ = source;
    if (!source.isEmpty()) {
        updateSmartPanel(address, typeHint, source);
    }
    refreshMemoryVisualization();
}

void MainWindow::activateModule(const QString &tag) {
    if (tag == "Memory") {
        showDock(memoryViewerDock_);
    } else if (tag == "Scanner") {
        showDock(scanDock_);
        showDock(resultsDock_);
    } else if (tag == "Code" || tag == "Scripts") {
        showDock(scriptDock_);
    } else if (tag == "Regions") {
        showDock(resultsDock_);
        showDock(trackingDock_);
    } else if (tag == "Threads") {
        showDock(trackingDock_);
    } else if (tag == "Symbols") {
        showDock(smartDock_);
    } else if (tag == "Dissector") {
        showDock(smartDock_);
        showDock(trackingDock_);
    } else if (tag == "Tools") {
        showDock(patchDock_);
    } else if (tag == "Settings") {
        showDock(settingsDock_);
    } else if (tag == "About") {
        showDock(aboutDock_);
    }
}

void MainWindow::showDock(QDockWidget *dock) {
    if (!dock) return;
    dock->show();
    dock->raise();
}

void MainWindow::pulseWatchRow(int row, const QColor &color) {
    pulseTableRow(watchTable_, row, color);
}

double MainWindow::decodeNumeric(const QByteArray &bytes, core::ValueType type, bool *ok) const {
    if (ok) *ok = false;
    if (bytes.isEmpty()) return 0.0;
    auto ensureSize = [&](int expected) -> bool {
        return bytes.size() >= expected;
    };
    switch (type) {
        case core::ValueType::Byte: {
            if (!ensureSize(static_cast<int>(sizeof(int8_t)))) return 0.0;
            int8_t v = 0;
            std::memcpy(&v, bytes.constData(), sizeof(v));
            if (ok) *ok = true;
            return v;
        }
        case core::ValueType::Int16: {
            if (!ensureSize(static_cast<int>(sizeof(int16_t)))) return 0.0;
            int16_t v = 0;
            std::memcpy(&v, bytes.constData(), sizeof(v));
            if (ok) *ok = true;
            return v;
        }
        case core::ValueType::Int32: {
            if (!ensureSize(static_cast<int>(sizeof(int32_t)))) return 0.0;
            int32_t v = 0;
            std::memcpy(&v, bytes.constData(), sizeof(v));
            if (ok) *ok = true;
            return v;
        }
        case core::ValueType::Int64: {
            if (!ensureSize(static_cast<int>(sizeof(int64_t)))) return 0.0;
            int64_t v = 0;
            std::memcpy(&v, bytes.constData(), sizeof(v));
            if (ok) *ok = true;
            return static_cast<double>(v);
        }
        case core::ValueType::Float: {
            if (!ensureSize(static_cast<int>(sizeof(float)))) return 0.0;
            float v = 0;
            std::memcpy(&v, bytes.constData(), sizeof(v));
            if (ok) *ok = true;
            return v;
        }
        case core::ValueType::Double: {
            if (!ensureSize(static_cast<int>(sizeof(double)))) return 0.0;
            double v = 0;
            std::memcpy(&v, bytes.constData(), sizeof(v));
            if (ok) *ok = true;
            return v;
        }
        default:
            return 0.0;
    }
}

double MainWindow::decodeRaw(uint64_t raw, core::ValueType type, bool *ok) const {
    double value = 0.0;
    switch (type) {
        case core::ValueType::Byte: value = static_cast<double>(unpackRaw<int8_t>(raw)); break;
        case core::ValueType::Int16: value = static_cast<double>(unpackRaw<int16_t>(raw)); break;
        case core::ValueType::Int32: value = static_cast<double>(unpackRaw<int32_t>(raw)); break;
        case core::ValueType::Int64: value = static_cast<double>(unpackRaw<int64_t>(raw)); break;
        case core::ValueType::Float: value = static_cast<double>(unpackRaw<float>(raw)); break;
        case core::ValueType::Double: value = unpackRaw<double>(raw); break;
        default:
            if (ok) *ok = false;
            return 0.0;
    }
    if (ok) *ok = true;
    return value;
}

void MainWindow::updateTrackedEntries() {
    if (!trackingList_) return;
    trackingList_->blockSignals(true);
    trackingList_->clear();
    for (uintptr_t addr : trackedAddresses_) {
        core::ValueType type = resultDisplayType_;
        if (auto it = trackedTypes_.find(addr); it != trackedTypes_.end()) type = it->second;
        QString valueText = QStringLiteral("??");
        if (target_ && target_->isAttached()) {
            QByteArray buf;
            switch (type) {
                case core::ValueType::Byte: {
                    int8_t v = 0; if (target_->readMemory(addr, &v, sizeof(v))) buf = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
                }
                case core::ValueType::Int16: {
                    int16_t v = 0; if (target_->readMemory(addr, &v, sizeof(v))) buf = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
                }
                case core::ValueType::Int32: {
                    int32_t v = 0; if (target_->readMemory(addr, &v, sizeof(v))) buf = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
                }
                case core::ValueType::Int64: {
                    int64_t v = 0; if (target_->readMemory(addr, &v, sizeof(v))) buf = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
                }
                case core::ValueType::Float: {
                    float v = 0; if (target_->readMemory(addr, &v, sizeof(v))) buf = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
                }
                case core::ValueType::Double: {
                    double v = 0; if (target_->readMemory(addr, &v, sizeof(v))) buf = QByteArray(reinterpret_cast<char *>(&v), sizeof(v)); break;
                }
                default:
                    break;
            }
            if (!buf.isEmpty()) {
                valueText = formatValue(buf, type);
            } else if (auto it = liveValues_.find(addr); it != liveValues_.end()) {
                valueText = formatRawValue(it->second, type);
            }
        }
        auto *item = new QTreeWidgetItem(trackingList_);
        item->setText(0, QString::asprintf("0x%llx", static_cast<unsigned long long>(addr)));
        item->setText(1, valueText);
    }
    trackingList_->blockSignals(false);
    if (trackingDock_) {
        if (trackedAddresses_.empty()) trackingDock_->hide();
        else trackingDock_->show();
    }
}

void MainWindow::recordSnapshot() {
    if (!scanner_ || scanner_->results().empty()) {
        QMessageBox::information(this, "Snapshots", "Run a scan before capturing a snapshot.");
        return;
    }
    snapshotValues_.clear();
    for (const auto &r : scanner_->results()) {
        snapshotValues_[r.address] = r.raw;
    }
    hasSnapshot_ = true;
    setStatusDetail(QStringLiteral("Snapshot stored."));
}

void MainWindow::compareSnapshot() {
    if (!hasSnapshot_) {
        QMessageBox::information(this, "Snapshots", "Take a snapshot first.");
        return;
    }
    if (!scanner_) {
        QMessageBox::information(this, "Snapshots", "No scan data available to compare.");
        return;
    }
    if (scanner_->results().empty()) {
        QMessageBox::information(this, "Snapshots", "No scan results loaded.");
        return;
    }
    size_t diffCount = 0;
    for (const auto &r : scanner_->results()) {
        auto it = snapshotValues_.find(r.address);
        if (it != snapshotValues_.end() && it->second != r.raw) {
            ++diffCount;
            trackedAddresses_.insert(r.address);
            trackedTypes_[r.address] = resultDisplayType_;
        }
    }
    updateTrackedEntries();
    if (trackingDock_ && diffCount > 0) trackingDock_->show();
    if (diffCount == 0) {
        QMessageBox::information(this, "Snapshots", "No differences detected.");
    } else {
        QMessageBox::information(this, "Snapshots",
                                 QString("%1 addresses differ from the snapshot and are being tracked.")
                                     .arg(diffCount));
    }
}

void MainWindow::updateSmartPanel(uintptr_t address, core::ValueType type, const QString &source) {
    if (!smartPanel_) return;
    auto sizeForType = [](core::ValueType t) {
        switch (t) {
            case core::ValueType::Byte: return 1;
            case core::ValueType::Int16: return 2;
            case core::ValueType::Int32: return 4;
            case core::ValueType::Int64: return 8;
            case core::ValueType::Float: return 4;
            case core::ValueType::Double: return 8;
            default: return 4;
        }
    };
    QStringList lines;
    lines << QString("Context: %1").arg(source.isEmpty() ? QStringLiteral("Global") : source);
    lines << QString("Address: 0x%1").arg(QString::number(address, 16));
    lines << QString("Type: %1").arg(typeToString(type));
    lines << QString("Alignment: %1 bytes").arg(sizeForType(type));
    if (auto it = guessedTypes_.find(address); it != guessedTypes_.end()) {
        lines << QString("Heuristic type: %1").arg(typeToString(it->second));
    }
    if (auto it = metaScores_.find(address); it != metaScores_.end()) {
        lines << QString("Confidence score: %1").arg(it->second, 0, 'f', 1);
    }
    if (pointerCandidates_.find(address) != pointerCandidates_.end()) {
        lines << QStringLiteral("Pointer candidate ✓");
    }
    if (auto it = metaGroups_.find(address); it != metaGroups_.end()) {
        lines << QString("Group: %1").arg(it->second);
    }

    QString valueText = QStringLiteral("(unavailable)");
    QByteArray scalarBuf;
    auto readScalar = [&](core::ValueType valueType) -> bool {
        int bytes = sizeForType(valueType);
        if (!target_ || !target_->isAttached() || bytes <= 0) return false;
        scalarBuf.resize(bytes);
        if (!target_->readMemory(address, scalarBuf.data(), static_cast<size_t>(bytes))) return false;
        valueText = formatValue(scalarBuf, valueType);
        return true;
    };
    if (!readScalar(type)) {
        if (auto it = liveValues_.find(address); it != liveValues_.end()) {
            valueText = formatRawValue(it->second, type);
        }
    }
    lines << QString("Value: %1").arg(valueText);

    if (type == core::ValueType::Int64 && target_ && target_->isAttached()) {
        uintptr_t pointed = 0;
        if (target_->readMemory(address, &pointed, sizeof(pointed))) {
            lines << QString("Pointer target: 0x%1").arg(QString::number(pointed, 16));
            QString childHex = hexDump(pointed, 32);
            if (!childHex.isEmpty()) {
                lines << "Child bytes:";
                lines << childHex.trimmed();
            }
        }
    }

    if (target_ && target_->isAttached()) {
        QString stackPreview = hexDump(address, 64);
        if (!stackPreview.isEmpty()) {
            lines << "Stack preview:";
            lines << stackPreview.trimmed();
        }
    }

    QStringList regs = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9"};
    lines << "Register palette:";
    for (int i = 0; i < regs.size(); ++i) {
        lines << QString("  %1 = 0x%2").arg(regs[i]).arg(QString::number(address + static_cast<uintptr_t>(i * 0x10), 16));
    }

    QString script = makePatchScript(address, QStringLiteral("90 90 90 90 90"));
    if (!script.isEmpty()) {
        lines << "Script preview:";
        lines << script;
    }

    smartPanel_->setPlainText(lines.join('\n'));
    if (smartDock_) smartDock_->show();
}

void MainWindow::applyGlobalStyle() {
    if (!qApp) return;
    const QPalette pal = qApp->palette();
    auto colorHex = [](const QColor &c, int alpha = -1) {
        QColor copy = c;
        if (alpha >= 0) copy.setAlpha(alpha);
        return copy.name(alpha >= 0 ? QColor::HexArgb : QColor::HexRgb);
    };
    QColor base = pal.window().color();
    QColor panel = pal.alternateBase().color().isValid() ? pal.alternateBase().color() : base.lighter(110);
    QColor border = pal.mid().color();
    QColor accent = pal.highlight().color();
    QColor text = pal.windowText().color();

    QString style = QString(R"(
        QToolBar {
            background: %1;
            spacing: 6px;
            border-bottom: 1px solid %4;
        }
        QToolBar QToolButton {
            background: %2;
            border: 1px solid %4;
            border-radius: 6px;
            padding: 4px 10px;
        }
        QToolBar QToolButton:hover {
            border-color: %3;
        }
        QGroupBox {
            border: 1px solid %4;
            border-radius: 8px;
            margin-top: 12px;
            padding-top: 8px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: %3;
        }
        QPushButton {
            background: %2;
            border: 1px solid %4;
            border-radius: 6px;
            padding: 6px 14px;
        }
        QPushButton:hover {
            border-color: %3;
        }
        QPushButton:disabled {
            opacity: 0.6;
        }
        QLineEdit, QComboBox, QSpinBox {
            background: %1;
            border: 1px solid %4;
            border-radius: 6px;
            padding: 4px 8px;
        }
        QPlainTextEdit {
            border: 1px solid %4;
            border-radius: 6px;
            background: %1;
        }
        QTableView {
            border: 1px solid %4;
            alternate-background-color: %2;
        }
        QHeaderView::section {
            background: %2;
            color: %5;
            border: none;
            padding: 6px 4px;
            font-weight: 500;
        }
        QListWidget {
            border: none;
        }
        QListWidget::item {
            padding: 6px 8px;
            border-radius: 4px;
        }
        QListWidget::item:selected {
            background: %3;
            color: %6;
        }
        QSplitter::handle {
            background: %2;
            margin: 1px;
        }
    )")
                             .arg(colorHex(panel))
                             .arg(colorHex(base.lighter(105)))
                             .arg(colorHex(accent))
                             .arg(colorHex(border))
                             .arg(colorHex(text))
                             .arg(colorHex(pal.highlightedText().color()));
    qApp->setStyleSheet(style);

    QFont uiFont = QFontDatabase::systemFont(QFontDatabase::GeneralFont);
    uiFont.setPointSize(std::max(10, uiFont.pointSize()));
    setFont(uiFont);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSize(uiFont.pointSize());
    if (resultsTable_) resultsTable_->setFont(mono);
    if (watchTable_) watchTable_->setFont(mono);
    if (notesEdit_) notesEdit_->setFont(mono);
    if (scriptEditor_) scriptEditor_->setFont(mono);
}

void MainWindow::openAutoAssemblerAt(uintptr_t address, const std::vector<uint8_t> &bytes) {
    if (!injector_ || !target_ || !target_->isAttached()) {
        QMessageBox::warning(this, "Auto Assembler", "Attach to a process first.");
        return;
    }
    std::vector<uint8_t> ctx = bytes;
    uintptr_t resolvedAddr = address ? address : globalAddress_;
    if (ctx.empty() && resolvedAddr != 0) {
        const int kDefaultSize = 10;
        ctx.resize(kDefaultSize);
        if (!target_->readMemory(resolvedAddr, ctx.data(), ctx.size())) {
            ctx.clear();
        }
    }
    if (!autoAsm_) {
        autoAsm_ = new AutoAssemblerDialog(injector_.get(), this);
        connect(autoAsm_, &AutoAssemblerDialog::scriptReady, this, &MainWindow::onScriptSubmitted);
    }
    autoAsm_->setInjectionContext(resolvedAddr, ctx);
    autoAsm_->show();
    autoAsm_->raise();
    autoAsm_->activateWindow();
    if (resolvedAddr != 0) {
        updateSmartPanel(resolvedAddr, core::ValueType::Int64, QStringLiteral("Auto assembler"));
    }
}

void MainWindow::openAobInjectionAt(uintptr_t address) {
    if (!target_ || !target_->isAttached() || !injector_) {
        QMessageBox::warning(this, "AoB Injection", "Attach to a process first.");
        return;
    }
    uintptr_t seedAddr = address ? address : globalAddress_;
    auto *dlg = new AobInjectionDialog(target_.get(), injector_.get(), this);
    if (seedAddr != 0) {
        dlg->setStartAddress(seedAddr);
    }
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
    dlg->raise();
    dlg->activateWindow();
    if (seedAddr != 0) {
        updateSmartPanel(seedAddr, core::ValueType::Int64, QStringLiteral("AoB injection"));
    }
}

void MainWindow::openPointerScannerAt(uintptr_t address) {
    if (!target_ || !target_->isAttached()) return;
    uintptr_t baseAddr = address;
    if (baseAddr == 0) baseAddr = globalAddress_;
    if (baseAddr == 0 && scanner_ && !scanner_->results().empty()) {
        baseAddr = scanner_->results().front().address;
    }
    if (!pointerScanner_) {
        pointerScanner_ = new PointerScannerDialog(target_.get(), this);
        connect(pointerScanner_, &PointerScannerDialog::pointerPreview, this,
                [this](const std::vector<core::PointerHit> &hits, int index) {
                    updatePointerGraph(hits, index);
                    if (pointerDock_) pointerDock_->show();
                });
        connect(pointerScanner_, &PointerScannerDialog::pointerSelected, this,
                [this](uintptr_t base, qint64 offset, uintptr_t finalAddr) {
                    WatchEntry w;
                    w.address = finalAddr;
                    w.type = core::ValueType::Int32;
                    w.description = QString("ptr 0x%1 + %2")
                        .arg(static_cast<unsigned long long>(base), 0, 16)
                        .arg(offset);
                    w.isPointer = true;
                    w.frozen = false;
                    w.stored.clear();
                    watches_.push_back(w);
                    populateWatchList(true);
                });
    }
    if (baseAddr != 0) {
        pointerScanner_->setTargetAddress(baseAddr);
    }
    pointerScanner_->show();
    pointerScanner_->raise();
    pointerScanner_->activateWindow();
    if (baseAddr != 0) {
        updateSmartPanel(baseAddr, core::ValueType::Int64, QStringLiteral("Pointer scanner"));
    }
}

AutoAssemblerDialog *MainWindow::ensureAutoAsmRunner() {
    if (!injector_) return nullptr;
    if (!autoAsmRunner_) {
        autoAsmRunner_ = new AutoAssemblerDialog(injector_.get(), this);
        autoAsmRunner_->hide();
    }
    return autoAsmRunner_;
}

void MainWindow::onScriptSubmitted(const QString &name, const QString &script) {
    WatchEntry w;
    w.description = name;
    w.isScript = true;
    w.scriptSource = script;
    w.type = core::ValueType::Byte;
    watches_.push_back(w);
    populateWatchList(true);
}

bool MainWindow::setScriptState(size_t index, bool enable) {
    if (index >= watches_.size()) return false;
    auto &w = watches_[index];
    if (!w.isScript || w.scriptActive == enable) return true;
    auto *runner = ensureAutoAsmRunner();
    if (!runner) return false;
    QString log;
    if (!runner->executeScriptText(w.scriptSource, enable, &log)) {
        QMessageBox::warning(this, "Auto Assembler", log.isEmpty() ? "Failed to execute script." : log);
        return false;
    }
    w.scriptActive = enable;
    populateWatchList(true);
    return true;
}

void MainWindow::promptPatchBytes(uintptr_t address) {
    if (!target_ || !injector_) {
        QMessageBox::warning(this, "Patch", "Attach to a process first.");
        return;
    }
    std::vector<uint8_t> buffer(8);
    QString defaultText;
    if (target_->readMemory(address, buffer.data(), buffer.size())) {
        defaultText = QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(buffer.data()), buffer.size()).toHex(' '));
    }
    bool ok = false;
    QString input = QInputDialog::getText(this, "Patch bytes",
                                          QString("Enter hex bytes for 0x%1").arg(QString::number(address, 16)),
                                          QLineEdit::Normal, defaultText, &ok);
    if (!ok || input.trimmed().isEmpty()) return;
    auto bytes = parseHexBytes(input);
    if (bytes.empty()) {
        QMessageBox::warning(this, "Patch", "No bytes provided.");
        return;
    }
    if (!injector_->patchBytes(address, bytes)) {
        QMessageBox::warning(this, "Patch", "Failed to patch bytes.");
    }
}

void MainWindow::recordScanSnapshot() {
    if (!scanner_) return;
    // Limit history to 1 undo level to save RAM
    if (scanHistory_.size() > 1) {
        scanHistory_.erase(scanHistory_.begin());
    }
    scanHistory_.push_back(scanner_->results());
    updateUndoState();
}

void MainWindow::resetScanHistory() {
    scanHistory_.clear();
    updateUndoState();
}

void MainWindow::updateUndoState() {
    if (!undoScanBtn_) return;
    bool canUndo = scanHistory_.size() > 1 && !scanInProgress_;
    undoScanBtn_->setEnabled(canUndo);
}

void MainWindow::onPatchBytes() {
    if (!injector_) return;
    uintptr_t addr = parseAddress(patchAddressEdit_->text());
    if (addr == 0) {
        QMessageBox::warning(this, "Patch", "Invalid address");
        return;
    }
    auto bytes = parseHexBytes(patchBytesEdit_->text());
    if (bytes.empty()) {
        QMessageBox::warning(this, "Patch", "No bytes provided");
        return;
    }
    if (!injector_->patchBytes(addr, bytes)) {
        QMessageBox::warning(this, "Patch", "Failed to patch bytes");
        return;
    }
    QMessageBox::information(this, "Patch", "Patched bytes");
}

void MainWindow::onRestorePatch() {
    if (!injector_) return;
    uintptr_t addr = parseAddress(patchAddressEdit_->text());
    if (!injector_->restore(addr)) {
        QMessageBox::warning(this, "Restore", "No patch found or failed to restore");
        return;
    }
    QMessageBox::information(this, "Restore", "Restored original bytes");
}
void MainWindow::onTrackValue(uintptr_t address, core::ValueType type, const QString &label) {
    if (address == 0) return;
    trackedAddresses_.insert(address);
    trackedTypes_[address] = type;
    updateTrackedEntries();
    if (trackingDock_) trackingDock_->show();
    updateSmartPanel(address, type, label.isEmpty() ? QStringLiteral("Tracked") : label);
}
void MainWindow::showSpark(uintptr_t address) {
    if (address == 0) return;
    sparkTimes_[address] = QDateTime::currentMSecsSinceEpoch();
}

void MainWindow::analyzeMetaResults() {
    metaScores_.clear();
    guessedTypes_.clear();
    metaGroups_.clear();
    pointerCandidates_.clear();
    if (!target_ || !target_->isAttached() || !scanner_) return;
    cachedRegions_ = target_->regions();
    const auto &res = scanner_->results();
    if (res.empty()) return;
    constexpr size_t kLimit = 2048;
    size_t limit = std::min<size_t>(res.size(), kLimit);
    std::vector<uintptr_t> addresses;
    addresses.reserve(limit);
    for (size_t i = 0; i < limit; ++i) addresses.push_back(res[i].address);
    std::sort(addresses.begin(), addresses.end());
    constexpr uintptr_t kGroupGap = 32;
    std::vector<uintptr_t> groupBuffer;
    auto flushGroup = [&]() {
        if (groupBuffer.size() > 1) {
            QString label = QString("Cluster 0x%1 (%2 entries)")
                                .arg(static_cast<unsigned long long>(groupBuffer.front()), 0, 16)
                                .arg(groupBuffer.size());
            for (auto addr : groupBuffer) metaGroups_[addr] = label;
        }
        groupBuffer.clear();
    };
    uintptr_t previous = 0;
    for (uintptr_t addr : addresses) {
        if (groupBuffer.empty() || addr - previous <= kGroupGap) {
            groupBuffer.push_back(addr);
        } else {
            flushGroup();
            groupBuffer.push_back(addr);
        }
        previous = addr;
    }
    flushGroup();

    for (size_t i = 0; i < limit; ++i) {
        uintptr_t addr = res[i].address;
        double score = 0.0;
        core::ValueType guess = resultDisplayType_;
        std::array<unsigned char, 16> buffer{};
        bool hasBytes = target_->readMemory(addr, buffer.data(), buffer.size());
        bool asciiCandidate = false;
        if (hasBytes) {
            int printable = 0;
            for (unsigned char ch : buffer) {
                if (ch == 0) continue;
                if (ch >= 32 && ch <= 126) ++printable;
            }
            if (printable >= 6) {
                asciiCandidate = true;
                score += 25.0;
                guess = core::ValueType::String;
            }
        }

        uintptr_t possiblePtr = 0;
        if (hasBytes && buffer.size() >= sizeof(uintptr_t)) {
            std::memcpy(&possiblePtr, buffer.data(), sizeof(uintptr_t));
            if (looksLikePointer(possiblePtr)) {
                pointerCandidates_.insert(addr);
                score += 40.0;
            }
        }

        if (!asciiCandidate && hasBytes) {
            float fv = 0.f;
            double dv = 0.0;
            std::memcpy(&fv, buffer.data(), std::min(sizeof(fv), buffer.size()));
            std::memcpy(&dv, buffer.data(), std::min(sizeof(dv), buffer.size()));
            if (std::isfinite(fv) && std::abs(fv) < 1e6f) {
                guess = core::ValueType::Float;
                score += 15.0;
            } else if (std::isfinite(dv) && std::abs(dv) < 1e12) {
                guess = core::ValueType::Double;
                score += 12.0;
            }
        }

        if (auto it = metaGroups_.find(addr); it != metaGroups_.end()) score += 10.0;
        if (const auto *region = regionFor(addr)) {
            if (region->perms.find('w') != std::string::npos) score += 5.0;
            if (region->perms.find('x') != std::string::npos) score -= 3.0;
        }

        metaScores_[addr] = score;
        guessedTypes_[addr] = guess;
    }
}

bool MainWindow::looksLikePointer(uintptr_t value) const {
    if (value == 0) return false;
    const auto *region = regionFor(value);
    if (!region) return false;
    return region->perms.find('r') != std::string::npos;
}

const core::MemoryRegion *MainWindow::regionFor(uintptr_t address) const {
    for (const auto &region : cachedRegions_) {
        if (address >= region.start && address < region.end) return &region;
    }
    return nullptr;
}

QString MainWindow::metaSummary(uintptr_t address) const {
    QStringList parts;
    if (auto it = metaScores_.find(address); it != metaScores_.end()) {
        parts << QString("Score: %1").arg(it->second, 0, 'f', 1);
    }
    if (auto it = guessedTypes_.find(address); it != guessedTypes_.end()) {
        parts << QString("Heuristic type: %1").arg(typeToString(it->second));
    }
    if (pointerCandidates_.find(address) != pointerCandidates_.end()) {
        parts << QStringLiteral("Pointer candidate");
    }
    if (auto it = metaGroups_.find(address); it != metaGroups_.end()) {
        parts << it->second;
    }
    if (const auto *region = regionFor(address)) {
        parts << QString("Region: %1 %2").arg(QString::fromStdString(region->perms))
                                           .arg(QString::fromStdString(region->path));
    }
    return parts.join('\n');
}

void MainWindow::updateResultsCount() {
    if (!resultsCountLabel_) return;
    size_t count = scanner_ ? scanner_->results().size() : 0;
    resultsCountLabel_->setText(QString("%1 result%2")
                                    .arg(static_cast<qulonglong>(count))
                                    .arg(count == 1 ? "" : "s"));
}

QString MainWindow::readBytesHex(uintptr_t address, int count) const {
    if (address == 0 || count <= 0) return QString();
    if (!target_ || !target_->isAttached()) return QString();
    QByteArray buffer(count, 0);
    if (!target_->readMemory(address, buffer.data(), static_cast<size_t>(buffer.size()))) return QString();
    QStringList tokens;
    for (int i = 0; i < buffer.size(); ++i) {
        tokens << QString::asprintf("%02X", static_cast<unsigned char>(buffer[i]));
    }
    return tokens.join(' ');
}

void MainWindow::persistSetting(const QString &key, const QVariant &value) {
    QSettings settings(QString::fromLatin1(kSettingsOrg), QString::fromLatin1(kSettingsApp));
    settings.setValue(key, value);
}

void MainWindow::loadSettings() {
    QSettings settings(QString::fromLatin1(kSettingsOrg), QString::fromLatin1(kSettingsApp));
    bool startMaximized = settings.value("ui/startMaximized", false).toBool();
    confirmDetach_ = settings.value("ui/confirmDetach", true).toBool();
    keepNotesVisible_ = settings.value("ui/notesVisible", false).toBool();
    int defaultType = settings.value("scan/defaultTypeIndex", typeCombo_ ? typeCombo_->currentIndex() : 2).toInt();
    int defaultMode = settings.value("scan/defaultModeIndex", modeCombo_ ? modeCombo_->currentIndex() : 0).toInt();
    bool fastScan = settings.value("scan/fastScan", fastScanCheck_ ? fastScanCheck_->isChecked() : true).toBool();
    bool skipMasked = settings.value("scan/skipMasked", skipMaskedCheck_ ? skipMaskedCheck_->isChecked() : false).toBool();
    bool autoRefresh = settings.value("watch/autoRefresh", autoRefreshCheck_ ? autoRefreshCheck_->isChecked() : true).toBool();
    int refreshInterval = settings.value("watch/interval", refreshIntervalSpin_ ? refreshIntervalSpin_->value() : 250).toInt();
    int sparkDuration = settings.value("watch/sparkDuration", static_cast<int>(sparkWindowMs_)).toInt();

    auto applyComboPreference = [](QComboBox *primary, QComboBox *mirror, int value) {
        if (!primary || primary->count() == 0) return;
        int index = std::clamp(value, 0, primary->count() - 1);
        primary->setCurrentIndex(index);
        if (mirror) {
            QSignalBlocker blocker(mirror);
            if (mirror->count() > 0) {
                int mirrorIndex = std::clamp(index, 0, mirror->count() - 1);
                mirror->setCurrentIndex(mirrorIndex);
            }
        }
    };

    applyComboPreference(typeCombo_, settingsTypeCombo_, defaultType);
    applyComboPreference(modeCombo_, settingsModeCombo_, defaultMode);

    if (fastScanCheck_) fastScanCheck_->setChecked(fastScan);
    if (settingsFastScanCheck_) {
        QSignalBlocker blocker(settingsFastScanCheck_);
        settingsFastScanCheck_->setChecked(fastScan);
    }
    if (skipMaskedCheck_) skipMaskedCheck_->setChecked(skipMasked);
    if (settingsSkipMaskedCheck_) {
        QSignalBlocker blocker(settingsSkipMaskedCheck_);
        settingsSkipMaskedCheck_->setChecked(skipMasked);
    }

    if (refreshIntervalSpin_) refreshIntervalSpin_->setValue(refreshInterval);
    if (settingsRefreshIntervalSpin_) {
        QSignalBlocker blocker(settingsRefreshIntervalSpin_);
        settingsRefreshIntervalSpin_->setValue(refreshInterval);
    }

    if (autoRefreshCheck_) autoRefreshCheck_->setChecked(autoRefresh);
    if (settingsAutoRefreshCheck_) {
        QSignalBlocker blocker(settingsAutoRefreshCheck_);
        settingsAutoRefreshCheck_->setChecked(autoRefresh);
    }

    sparkWindowMs_ = sparkDuration > 0 ? sparkDuration : sparkWindowMs_;
    if (sparkDurationSpin_) {
        QSignalBlocker blocker(sparkDurationSpin_);
        sparkDurationSpin_->setValue(static_cast<int>(sparkWindowMs_));
    }

    if (startMaximizedCheck_) {
        QSignalBlocker blocker(startMaximizedCheck_);
        startMaximizedCheck_->setChecked(startMaximized);
    }
    if (confirmDetachCheck_) {
        QSignalBlocker blocker(confirmDetachCheck_);
        confirmDetachCheck_->setChecked(confirmDetach_);
    }
    if (notesVisibleCheck_) {
        QSignalBlocker blocker(notesVisibleCheck_);
        notesVisibleCheck_->setChecked(keepNotesVisible_);
    }
    if (notesDock_) {
        if (keepNotesVisible_) notesDock_->show();
        else notesDock_->hide();
    }

    if (startMaximized) {
        QTimer::singleShot(0, this, [this]() { showMaximized(); });
    }
}

QString MainWindow::makePatchScript(uintptr_t address, const QString &patchBytes, bool viaAob) const {
    if (address == 0) return QString();
    QString trimmed = patchBytes.trimmed();
    QStringList patchTokens = trimmed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    if (patchTokens.isEmpty()) {
        patchTokens = {QStringLiteral("90"), QStringLiteral("90"), QStringLiteral("90"), QStringLiteral("90"), QStringLiteral("90")};
    }
    QString patchLine = patchTokens.join(' ');
    int byteCount = patchTokens.size();
    QString original = readBytesHex(address, byteCount);
    QString addrStr = QString::asprintf("0x%llx", static_cast<unsigned long long>(address));
    QStringList lines;
    lines << QStringLiteral("[ENABLE]");
    if (viaAob) {
        QString pattern = original.isEmpty() ? patchLine : original;
        lines << QStringLiteral("aobscanmodule(INJECT,$process,%1)").arg(pattern);
        lines << QStringLiteral("patch INJECT %1").arg(patchLine);
    } else {
        lines << QStringLiteral("patch %1 %2").arg(addrStr, patchLine);
    }
    if (!original.isEmpty()) {
        lines << QStringLiteral("; original %1").arg(original);
    }
    lines << QString();
    lines << QStringLiteral("[DISABLE]");
    lines << (viaAob ? QStringLiteral("restore INJECT") : QStringLiteral("restore %1").arg(addrStr));
    return lines.join('\n');
}

void MainWindow::updatePointerGraph(uintptr_t base, qint64 offset, uintptr_t finalAddr) {
    if (!pointerScene_) return;
    pointerScene_->clear();
    const int nodeWidth = 140;
    const int nodeHeight = 60;
    const int spacing = 170;
    auto addNode = [](QGraphicsScene *scene, const QString &title, double x, double y) {
        auto rect = scene->addRect(x, y, 140, 60, QPen(Qt::cyan, 2), QBrush(QColor(10, 20, 40)));
        auto *text = scene->addText(title);
        text->setDefaultTextColor(Qt::white);
        text->setPos(x + 10, y + 10);
        return rect;
    };
    double y = 20;
    auto *baseRect = addNode(pointerScene_, QString("Base\n0x%1").arg(QString::number(base, 16)), 10, y);
    QString pointerText = QString("Ptr = [0x%1]\nOffset %2").arg(QString::number(base, 16)).arg(offset);
    auto *offsetRect = addNode(pointerScene_, pointerText, 10 + spacing, y);
    auto *finalRect = addNode(pointerScene_, QString("Final\n0x%1").arg(QString::number(finalAddr, 16)), 10 + spacing * 2, y);
    auto drawArrow = [&](QGraphicsItem *from, QGraphicsItem *to) {
        QPointF start = from->sceneBoundingRect().center();
        QPointF end = to->sceneBoundingRect().center();
        pointerScene_->addLine(QLineF(start + QPointF(70, 0), end - QPointF(70, 0)), QPen(QColor("#ffa94d"), 2));
    };
    drawArrow(baseRect, offsetRect);
    drawArrow(offsetRect, finalRect);
    pointerScene_->setSceneRect(pointerScene_->itemsBoundingRect().adjusted(-20, -20, 20, 20));
}

void MainWindow::updatePointerGraph(const std::vector<core::PointerHit> &hits, int highlightIndex) {
    if (!pointerScene_) return;
    pointerScene_->clear();
    if (hits.empty()) {
        auto *label = pointerScene_->addText("No pointer hits yet.");
        label->setDefaultTextColor(Qt::white);
        pointerScene_->setSceneRect(label->boundingRect().adjusted(-20, -20, 20, 20));
        return;
    }
    int clampedIndex = std::clamp(highlightIndex, 0, static_cast<int>(hits.size()) - 1);
    int start = std::max(0, clampedIndex - 50);
    int end = std::min<int>(hits.size(), clampedIndex + 51);
    const int columns = 10;
    const double colSpacing = 180.0;
    const double rowSpacing = 120.0;
    std::vector<QPointF> centers;
    centers.reserve(end - start);
    for (int i = start; i < end; ++i) {
        int rel = i - start;
        int row = rel / columns;
        int col = rel % columns;
        double x = 20 + col * colSpacing;
        double y = 20 + row * rowSpacing;
        bool highlight = (i == clampedIndex);
        QColor penColor = highlight ? QColor("#ff7b54") : QColor("#00c2ff");
        QColor fill = highlight ? QColor(255, 123, 84, 80) : QColor(0, 194, 255, 50);
        auto rect = pointerScene_->addRect(x, y, 150, 80, QPen(penColor, 2), QBrush(fill));
        QString textBlock = QString("Base 0x%1\nOffset %2\nFinal 0x%3")
                                .arg(QString::number(hits[i].baseAddress, 16))
                                .arg(hits[i].offset)
                                .arg(QString::number(hits[i].finalAddress, 16));
        auto *text = pointerScene_->addText(textBlock);
        text->setDefaultTextColor(Qt::white);
        text->setPos(x + 8, y + 8);
        if (highlight) {
            auto *tag = pointerScene_->addText("SELECTED");
            tag->setDefaultTextColor(QColor("#ffcf66"));
            tag->setPos(x + 8, y - 18);
        }
        centers.push_back(rect->sceneBoundingRect().center());
    }
    for (int i = 0; i < static_cast<int>(centers.size()) - 1; ++i) {
        pointerScene_->addLine(QLineF(centers[i] + QPointF(30, 0), centers[i + 1] - QPointF(30, 0)), QPen(QColor("#ffa94d"), 1.5));
    }
    pointerScene_->setSceneRect(pointerScene_->itemsBoundingRect().adjusted(-30, -30, 30, 30));
}

void MainWindow::refreshMemoryVisualization() {
    if (!memoryScene_ || !memoryVizDock_ || !memoryVizDock_->isVisible()) return;
    memoryScene_->clear();
    if (!target_ || !target_->isAttached() || globalAddress_ == 0) return;
    constexpr int grid = 32;
    const size_t total = grid * grid;
    std::vector<uint8_t> buf(total);
    if (!target_->readMemory(globalAddress_, buf.data(), buf.size())) return;
    QImage img(grid, grid, QImage::Format_RGB32);
    for (int y = 0; y < grid; ++y) {
        for (int x = 0; x < grid; ++x) {
            size_t idx = static_cast<size_t>(y) * grid + x;
            uint8_t b = buf[idx];
            QColor col(b, (b * 5) % 256, 255 - b);
            img.setPixelColor(x, y, col);
        }
    }
    QSize targetSize = memoryVizView_ ? memoryVizView_->viewport()->size() : QSize(grid * 4, grid * 4);
    if (targetSize.width() == 0 || targetSize.height() == 0) targetSize = QSize(grid * 4, grid * 4);
    QPixmap pix = QPixmap::fromImage(img.scaled(targetSize, Qt::KeepAspectRatio, Qt::FastTransformation));
    memoryScene_->addPixmap(pix);
    memoryScene_->setSceneRect(pix.rect());
}

void MainWindow::pulseTableRow(QTableWidget *table, int row, const QColor &color, int duration) {
    if (!table || row < 0 || row >= table->rowCount()) return;
    for (int c = 0; c < table->columnCount(); ++c) {
        if (auto *item = table->item(row, c)) {
            item->setBackground(color);
        }
    }
    QTimer::singleShot(duration, table, [table, row]() {
        if (!table) return;
        for (int c = 0; c < table->columnCount(); ++c) {
            if (auto *item = table->item(row, c)) {
                item->setBackground(Qt::NoBrush);
            }
        }
    });
}
