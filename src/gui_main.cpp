/**
 * @file gui_main.cpp
 * @brief Modern native Qt interface for the KernelVault C++ engine.
 *
 * Provides GUI access to vault initialization, batch and directory encryption,
 * secure shredding, record decryption, in-place cryptographic HMAC verification,
 * and tabular vault inventory inspection.
 */

#include "KeyDerivation.hpp"
#include "VaultManager.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QThread>
#include <QVBoxLayout>
#include <QWidget>

#include <exception>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>
#include <utility>
#include <ctime>
#include <sys/stat.h>

namespace {

std::filesystem::path toPath(const QString& value) {
    const QByteArray utf8 = value.toUtf8();
    return std::filesystem::path(std::string(utf8.constData(),
                                             static_cast<size_t>(utf8.size())));
}

QString formatBytes(uint64_t bytes) {
    if (bytes < 1024) return QString("%1 B").arg(bytes);
    if (bytes < 1024 * 1024) return QString("%1 KiB").arg(QString::number(static_cast<double>(bytes) / 1024.0, 'f', 2));
    if (bytes < 1024ULL * 1024 * 1024) return QString("%1 MiB").arg(QString::number(static_cast<double>(bytes) / (1024.0 * 1024.0), 'f', 2));
    return QString("%1 GiB").arg(QString::number(static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0), 'f', 2));
}

QString formatMode(uint32_t mode) {
    if (mode == 0) return "---------";
    QString s;
    s += (mode & S_IRUSR) ? 'r' : '-';
    s += (mode & S_IWUSR) ? 'w' : '-';
    s += (mode & S_IXUSR) ? 'x' : '-';
    s += (mode & S_IRGRP) ? 'r' : '-';
    s += (mode & S_IWGRP) ? 'w' : '-';
    s += (mode & S_IXGRP) ? 'x' : '-';
    s += (mode & S_IROTH) ? 'r' : '-';
    s += (mode & S_IWOTH) ? 'w' : '-';
    s += (mode & S_IXOTH) ? 'x' : '-';
    return s;
}

QString formatTime(uint32_t epoch) {
    if (epoch == 0) return "N/A";
    time_t t = static_cast<time_t>(epoch);
    struct tm tm_info{};
    localtime_r(&t, &tm_info);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    return QString::fromUtf8(buf);
}

class MainWindow final : public QMainWindow {
public:
    MainWindow() {
        setWindowTitle("KernelVault - Secure Linux Storage");
        setMinimumSize(920, 680);
        resize(1080, 740);

        auto* central = new QWidget(this);
        auto* root = new QVBoxLayout(central);
        root->setContentsMargins(28, 24, 28, 24);
        root->setSpacing(14);

        auto* heading = new QLabel("KernelVault", central);
        heading->setObjectName("heading");
        auto* subtitle = new QLabel(
            "High-Assurance Linux Kernel-Assisted Encrypted Storage with POSIX Metadata Preservation.", central);
        subtitle->setObjectName("muted");
        subtitle->setWordWrap(true);
        root->addWidget(heading);
        root->addWidget(subtitle);

        root->addWidget(buildVaultPanel(central));
        root->addWidget(buildOperations(central), 1);

        m_resultLabel = new QLabel("Choose a vault directory to begin.", central);
        m_resultLabel->setObjectName("result");
        m_resultLabel->setWordWrap(true);
        root->addWidget(m_resultLabel);
        setCentralWidget(central);

        setStyleSheet(R"(
            QMainWindow, QWidget { background: #0f172a; color: #f8fafc; font-size: 13px; font-family: 'Segoe UI', Inter, sans-serif; }
            QLabel#heading { font-size: 26px; font-weight: 700; color: #38bdf8; }
            QLabel#muted { color: #94a3b8; }
            QGroupBox { background: #1e293b; border: 1px solid #334155; border-radius: 10px;
                        margin-top: 10px; padding: 12px; font-weight: 600; color: #e2e8f0; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #38bdf8; }
            QLineEdit, QComboBox { background: #0f172a; border: 1px solid #475569; color: #f8fafc;
                                  border-radius: 6px; padding: 7px 10px; min-height: 20px; }
            QLineEdit:focus, QComboBox:focus { border: 1px solid #38bdf8; }
            QPushButton { background: #334155; border: 1px solid #475569; border-radius: 6px; color: #f8fafc;
                          padding: 8px 14px; font-weight: 600; }
            QPushButton:hover { background: #475569; }
            QPushButton:disabled { color: #64748b; background: #1e293b; border-color: #334155; }
            QPushButton#primary { color: #ffffff; background: #0284c7; border-color: #0284c7; }
            QPushButton#primary:hover { background: #0369a1; }
            QPushButton#danger { color: #ffffff; background: #dc2626; border-color: #dc2626; }
            QPushButton#danger:hover { background: #b91c1c; }
            QTabWidget::pane { background: #1e293b; border: 1px solid #334155;
                               border-radius: 8px; top: -1px; }
            QTabBar::tab { background: #0f172a; color: #94a3b8; padding: 9px 18px; margin-right: 4px;
                           border-top-left-radius: 6px; border-top-right-radius: 6px; border: 1px solid #334155; }
            QTabBar::tab:selected { color: #38bdf8; background: #1e293b; font-weight: 700; border-bottom: none; }
            QTableWidget { background: #0f172a; border: 1px solid #334155; border-radius: 6px; gridline-color: #1e293b; color: #f8fafc; }
            QHeaderView::section { background: #1e293b; color: #94a3b8; font-weight: 700; border: 1px solid #334155; padding: 6px; }
            QLabel#statusReady { color: #34d399; font-weight: 700; }
            QLabel#statusWarning { color: #fbbf24; font-weight: 700; }
            QLabel#result { padding: 6px 2px; color: #38bdf8; font-weight: 500; }
            QCheckBox { color: #e2e8f0; font-weight: 500; }
        )");

        connect(m_vaultPath, &QLineEdit::editingFinished, this, [this] { refreshVaultState(); });
        refreshVaultState();
    }

    ~MainWindow() override {
        if (m_worker != nullptr) {
            m_worker->wait();
        }
    }

private:
    QLineEdit* m_vaultPath{};
    QLabel* m_vaultState{};
    QLabel* m_engineState{};
    QPushButton* m_initializeButton{};
    QTabWidget* m_tabs{};

    // Encrypt tab controls
    QLineEdit* m_encryptInput{};
    QCheckBox* m_shredCheckbox{};
    QLineEdit* m_encryptPassword{};
    QPushButton* m_encryptButton{};
    std::vector<std::string> m_selectedFiles;
    bool m_isDirectoryMode{false};

    // Decrypt tab controls
    QComboBox* m_decryptRecord{};
    QLineEdit* m_decryptOutput{};
    QLineEdit* m_decryptPassword{};
    QPushButton* m_decryptButton{};

    // Inventory tab controls
    QTableWidget* m_inventoryTable{};
    QPushButton* m_verifyButton{};
    QPushButton* m_deleteButton{};
    QPushButton* m_auditAllButton{};
    QPushButton* m_refreshButton{};

    QLabel* m_resultLabel{};
    QThread* m_worker{};
    bool m_vaultInitialized{false};

    QWidget* buildVaultPanel(QWidget* parent) {
        auto* group = new QGroupBox("1. Vault Storage", parent);
        auto* layout = new QVBoxLayout(group);
        auto* pathRow = new QHBoxLayout();
        m_vaultPath = new QLineEdit(QDir::homePath() + "/kvault-vault", group);
        m_vaultPath->setPlaceholderText("Vault directory path");
        auto* browse = new QPushButton("Choose folder", group);
        connect(browse, &QPushButton::clicked, this, [this] {
            const QString selected = QFileDialog::getExistingDirectory(
                this, "Choose vault folder", m_vaultPath->text());
            if (!selected.isEmpty()) {
                m_vaultPath->setText(selected);
                refreshVaultState();
            }
        });
        pathRow->addWidget(m_vaultPath, 1);
        pathRow->addWidget(browse);
        layout->addLayout(pathRow);

        auto* stateRow = new QHBoxLayout();
        m_vaultState = new QLabel(group);
        m_engineState = new QLabel(group);
        m_initializeButton = new QPushButton("Initialize vault", group);
        connect(m_initializeButton, &QPushButton::clicked, this, [this] { initializeVault(); });
        stateRow->addWidget(m_vaultState, 1);
        stateRow->addWidget(m_engineState, 1);
        stateRow->addWidget(m_initializeButton);
        layout->addLayout(stateRow);
        return group;
    }

    QWidget* buildOperations(QWidget* parent) {
        m_tabs = new QTabWidget(parent);
        m_tabs->addTab(buildEncryptTab(m_tabs), "Encrypt Files / Folders");
        m_tabs->addTab(buildDecryptTab(m_tabs), "Decrypt Record");
        m_tabs->addTab(buildInventoryTab(m_tabs), "Vault Inventory & Audit");
        return m_tabs;
    }

    QWidget* buildEncryptTab(QWidget* parent) {
        auto* page = new QWidget(parent);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(18, 16, 18, 16);
        layout->setSpacing(12);

        auto* form = new QFormLayout();

        auto* fileRow = new QWidget(page);
        auto* fileLayout = new QHBoxLayout(fileRow);
        fileLayout->setContentsMargins(0, 0, 0, 0);
        m_encryptInput = new QLineEdit(fileRow);
        m_encryptInput->setReadOnly(true);
        m_encryptInput->setPlaceholderText("Select files or folder to encrypt...");

        auto* chooseFiles = new QPushButton("Select Files...", fileRow);
        connect(chooseFiles, &QPushButton::clicked, this, [this] {
            const QStringList files = QFileDialog::getOpenFileNames(this, "Select plaintext files to encrypt");
            if (!files.isEmpty()) {
                m_selectedFiles.clear();
                for (const auto& f : files) m_selectedFiles.push_back(f.toStdString());
                m_isDirectoryMode = false;
                m_encryptInput->setText(QString("%1 file(s) selected").arg(files.size()));
            }
        });

        auto* chooseFolder = new QPushButton("Select Folder...", fileRow);
        connect(chooseFolder, &QPushButton::clicked, this, [this] {
            const QString dir = QFileDialog::getExistingDirectory(this, "Select directory tree to encrypt");
            if (!dir.isEmpty()) {
                m_selectedFiles.clear();
                m_selectedFiles.push_back(dir.toStdString());
                m_isDirectoryMode = true;
                m_encryptInput->setText(QString("[Directory] %1").arg(dir));
            }
        });

        fileLayout->addWidget(m_encryptInput, 1);
        fileLayout->addWidget(chooseFiles);
        fileLayout->addWidget(chooseFolder);
        form->addRow("Plaintext Source", fileRow);

        m_encryptPassword = new QLineEdit(page);
        m_encryptPassword->setEchoMode(QLineEdit::Password);
        m_encryptPassword->setPlaceholderText("Enter master passphrase");
        form->addRow("Master Passphrase", m_encryptPassword);

        m_shredCheckbox = new QCheckBox("Securely shred plaintext source file(s) after encryption (--shred)", page);
        form->addRow("", m_shredCheckbox);

        layout->addLayout(form);

        auto* note = new QLabel(
            "RFC 2898 Dual-Key PBKDF2 derives independent AES-256 and HMAC-SHA256 keys. "
            "POSIX modes and timestamps are preserved inside the authenticated 96-byte header.", page);
        note->setObjectName("muted");
        note->setWordWrap(true);
        layout->addWidget(note);

        m_encryptButton = new QPushButton("Encrypt and Store", page);
        m_encryptButton->setObjectName("primary");
        connect(m_encryptButton, &QPushButton::clicked, this, [this] { encryptSelectedFiles(); });
        layout->addWidget(m_encryptButton, 0, Qt::AlignLeft);
        layout->addStretch(1);
        return page;
    }

    QWidget* buildDecryptTab(QWidget* parent) {
        auto* page = new QWidget(parent);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(18, 16, 18, 16);
        layout->setSpacing(12);

        auto* form = new QFormLayout();
        m_decryptRecord = new QComboBox(page);
        form->addRow("Protected Record", m_decryptRecord);

        auto* outputRow = new QWidget(page);
        auto* outputLayout = new QHBoxLayout(outputRow);
        outputLayout->setContentsMargins(0, 0, 0, 0);
        m_decryptOutput = new QLineEdit(outputRow);
        m_decryptOutput->setPlaceholderText("Restored file or directory path...");
        auto* chooseOutput = new QPushButton("Save As...", outputRow);
        connect(chooseOutput, &QPushButton::clicked, this, [this] {
            QString suggested = QDir::homePath() + "/restored";
            if (m_decryptRecord->currentIndex() >= 0) {
                QString rec = m_decryptRecord->currentText();
                if (rec.endsWith(".kvdir")) {
                    suggested = QDir::homePath() + "/" + rec.left(rec.size() - 6);
                    const QString sel = QFileDialog::getExistingDirectory(this, "Choose destination directory", suggested);
                    if (!sel.isEmpty()) m_decryptOutput->setText(sel);
                    return;
                }
                suggested = QDir::homePath() + "/" + rec;
            }
            const QString selected = QFileDialog::getSaveFileName(this, "Choose destination path", suggested);
            if (!selected.isEmpty()) {
                m_decryptOutput->setText(selected);
            }
        });
        outputLayout->addWidget(m_decryptOutput, 1);
        outputLayout->addWidget(chooseOutput);
        form->addRow("Restoration Target", outputRow);

        m_decryptPassword = new QLineEdit(page);
        m_decryptPassword->setEchoMode(QLineEdit::Password);
        m_decryptPassword->setPlaceholderText("Enter the passphrase used for encryption");
        form->addRow("Master Passphrase", m_decryptPassword);
        layout->addLayout(form);

        auto* note = new QLabel(
            "KernelVault verifies the streaming HMAC-SHA256 before any plaintext is committed to disk. "
            "Permissions and timestamps are restored automatically.", page);
        note->setObjectName("muted");
        note->setWordWrap(true);
        layout->addWidget(note);

        auto* btnRow = new QHBoxLayout();
        m_decryptButton = new QPushButton("Verify and Restore Record", page);
        m_decryptButton->setObjectName("primary");
        connect(m_decryptButton, &QPushButton::clicked, this, [this] { decryptSelectedRecord(); });

        auto* decryptAllBtn = new QPushButton("Restore All to Folder...", page);
        connect(decryptAllBtn, &QPushButton::clicked, this, [this] { decryptAllRecordsToFolder(); });

        btnRow->addWidget(m_decryptButton);
        btnRow->addWidget(decryptAllBtn);
        btnRow->addStretch(1);
        layout->addLayout(btnRow);
        layout->addStretch(1);
        return page;
    }

    QWidget* buildInventoryTab(QWidget* parent) {
        auto* page = new QWidget(parent);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(18, 16, 18, 16);
        layout->setSpacing(12);

        m_inventoryTable = new QTableWidget(page);
        m_inventoryTable->setColumnCount(7);
        m_inventoryTable->setHorizontalHeaderLabels({
            "Record Name", "Version", "Plaintext Size", "Vault Size", "Permissions", "Modified", "Status"
        });
        m_inventoryTable->horizontalHeader()->setStretchLastSection(true);
        m_inventoryTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        m_inventoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_inventoryTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_inventoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        connect(m_inventoryTable, &QTableWidget::cellDoubleClicked, this, [this](int row, int /*col*/) {
            if (row >= 0 && row < m_inventoryTable->rowCount()) {
                QString name = m_inventoryTable->item(row, 0)->text();
                m_decryptRecord->setCurrentText(name);
                m_tabs->setCurrentIndex(1);
            }
        });
        layout->addWidget(m_inventoryTable, 1);

        auto* btnRow = new QHBoxLayout();
        m_verifyButton = new QPushButton("Verify Integrity (HMAC)", page);
        connect(m_verifyButton, &QPushButton::clicked, this, [this] { verifySelectedRecord(); });

        m_auditAllButton = new QPushButton("Audit All Records", page);
        connect(m_auditAllButton, &QPushButton::clicked, this, [this] { auditAllRecords(); });

        m_deleteButton = new QPushButton("Delete Record", page);
        m_deleteButton->setObjectName("danger");
        connect(m_deleteButton, &QPushButton::clicked, this, [this] { deleteSelectedRecord(); });

        m_refreshButton = new QPushButton("Refresh", page);
        connect(m_refreshButton, &QPushButton::clicked, this, [this] { refreshVaultState(); });

        btnRow->addWidget(m_verifyButton);
        btnRow->addWidget(m_auditAllButton);
        btnRow->addWidget(m_deleteButton);
        btnRow->addStretch(1);
        btnRow->addWidget(m_refreshButton);
        layout->addLayout(btnRow);

        return page;
    }

    void refreshVaultState() {
        if (m_worker != nullptr || m_vaultPath == nullptr) {
            return;
        }
        try {
            kvault::VaultManager vault(toPath(m_vaultPath->text()));
            const kvault::VaultStatus status = vault.inspectStatus();
            m_vaultInitialized = status.is_initialized;
            m_vaultState->setObjectName(m_vaultInitialized ? "statusReady" : "statusWarning");
            m_vaultState->setText(m_vaultInitialized
                ? QString("Vault ready · %1 record(s) · %2")
                    .arg(status.file_count)
                    .arg(formatBytes(status.total_vault_bytes))
                : "Vault not initialized");
            m_engineState->setText(status.kernel_driver_available
                ? QString("Driver: Active (/dev/kvault v0x%1)").arg(QString::number(status.kernel_driver_version, 16))
                : "Driver: Inactive · Software Fallback");
            m_initializeButton->setEnabled(!m_vaultInitialized);

            m_decryptRecord->clear();
            for (const std::string& name : status.stored_files) {
                m_decryptRecord->addItem(QString::fromStdString(name));
            }
            if (status.stored_files.empty()) {
                m_decryptRecord->addItem("No protected records yet");
                m_decryptRecord->setEnabled(false);
            } else {
                m_decryptRecord->setEnabled(true);
            }
            m_decryptButton->setEnabled(m_vaultInitialized && !status.stored_files.empty());
            m_encryptButton->setEnabled(m_vaultInitialized);

            // Populate Inventory Table
            auto records = vault.listRecords();
            m_inventoryTable->setRowCount(static_cast<int>(records.size()));
            for (int row = 0; row < static_cast<int>(records.size()); ++row) {
                const auto& r = records[static_cast<size_t>(row)];
                m_inventoryTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(r.filename)));
                m_inventoryTable->setItem(row, 1, new QTableWidgetItem(QString("v%1").arg(r.version)));
                m_inventoryTable->setItem(row, 2, new QTableWidgetItem(formatBytes(r.original_size)));
                m_inventoryTable->setItem(row, 3, new QTableWidgetItem(formatBytes(r.payload_size)));
                m_inventoryTable->setItem(row, 4, new QTableWidgetItem(formatMode(r.posix_mode)));
                m_inventoryTable->setItem(row, 5, new QTableWidgetItem(formatTime(r.mtime_epoch)));

                auto* statusItem = new QTableWidgetItem(r.is_locked ? "LOCKED" : "READY");
                statusItem->setForeground(r.is_locked ? QColor(251, 191, 36) : QColor(52, 211, 153));
                m_inventoryTable->setItem(row, 6, statusItem);
            }

            if (!m_vaultInitialized) {
                m_resultLabel->setText("Initialize this vault before encrypting or decrypting files.");
            }
        } catch (const std::exception& error) {
            m_vaultInitialized = false;
            m_vaultState->setText("Vault status unavailable");
            m_engineState->setText(QString::fromUtf8(error.what()));
            m_initializeButton->setEnabled(false);
            m_encryptButton->setEnabled(false);
            m_decryptButton->setEnabled(false);
        }
    }

    void initializeVault() {
        if (m_vaultPath->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, "Vault path required", "Choose a directory for the vault first.");
            return;
        }
        if (QMessageBox::question(this, "Initialize vault",
                "Create the secure vault directory and metadata at this location?\n\n" + m_vaultPath->text())
            != QMessageBox::Yes) {
            return;
        }
        const auto vaultPath = toPath(m_vaultPath->text());
        runTask("Initializing vault…", [vaultPath] {
            try {
                kvault::VaultManager vault(vaultPath);
                return vault.initializeVault()
                    ? QString("Vault initialized and ready at %1").arg(QString::fromStdString(vaultPath.string()))
                    : QString("Could not initialize the vault. Check the selected path and permissions.");
            } catch (const std::exception& error) {
                return QString("Vault initialization failed: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void encryptSelectedFiles() {
        if (m_selectedFiles.empty() || m_encryptPassword->text().isEmpty()) {
            QMessageBox::warning(this, "Missing information", "Select files or folder and enter a passphrase.");
            return;
        }
        std::string secret = m_encryptPassword->text().toUtf8().toStdString();
        m_encryptPassword->clear();
        const auto vaultPath = toPath(m_vaultPath->text());
        const auto files = m_selectedFiles;
        const bool isDir = m_isDirectoryMode;
        const bool shred = m_shredCheckbox->isChecked();

        runTask("Encrypting and authenticating...", [vaultPath, files, isDir, shred, secret = std::move(secret)]() mutable {
            try {
                kvault::VaultManager vault(vaultPath);
                size_t success = 0;
                size_t fail = 0;

                if (isDir && !files.empty()) {
                    if (vault.encryptDirectory(files[0], secret)) {
                        success++;
                    } else {
                        fail++;
                    }
                } else {
                    for (const auto& f : files) {
                        if (vault.encryptFile(f, secret)) {
                            success++;
                            if (shred) {
                                kvault::VaultManager::shredFile(f);
                            }
                        } else {
                            fail++;
                        }
                    }
                }

                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Encryption complete: %1 succeeded, %2 failed.")
                    .arg(success).arg(fail);
            } catch (const std::exception& error) {
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Encryption failed: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void decryptSelectedRecord() {
        if (m_decryptRecord->currentIndex() < 0 || !m_decryptRecord->isEnabled() ||
            m_decryptOutput->text().trimmed().isEmpty() || m_decryptPassword->text().isEmpty()) {
            QMessageBox::warning(this, "Missing information",
                "Choose a protected record, an output path, and enter its passphrase.");
            return;
        }
        const std::string record = m_decryptRecord->currentText().toStdString();
        const auto vaultPath = toPath(m_vaultPath->text());
        const auto outputPath = toPath(m_decryptOutput->text());
        std::string secret = m_decryptPassword->text().toUtf8().toStdString();
        m_decryptPassword->clear();

        runTask("Verifying record HMAC, then restoring...", [vaultPath, outputPath, record, secret = std::move(secret)]() mutable {
            try {
                kvault::VaultManager vault(vaultPath);
                bool success = false;
                if (record.ends_with(".kvdir")) {
                    success = vault.decryptDirectory(record, outputPath, secret);
                } else {
                    success = vault.decryptFile(record, outputPath, secret);
                }
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return success
                    ? QString("Record authenticated and restored to %1").arg(QString::fromStdString(outputPath.string()))
                    : QString("Restore failed: Incorrect passphrase or damaged record.");
            } catch (const std::exception& error) {
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Restore failed: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void decryptAllRecordsToFolder() {
        const QString dest = QFileDialog::getExistingDirectory(this, "Choose folder to restore all records into");
        if (dest.isEmpty()) return;

        bool ok = false;
        QString pass = QInputDialog::getText(this, "Restore All Records",
            "Enter master passphrase to restore all records:",
            QLineEdit::Password, "", &ok);
        if (!ok || pass.isEmpty()) return;

        std::string secret = pass.toUtf8().toStdString();
        const auto vaultPath = toPath(m_vaultPath->text());
        const auto outDir = toPath(dest);

        runTask("Restoring all vault records...", [vaultPath, outDir, secret = std::move(secret)]() mutable {
            try {
                kvault::VaultManager vault(vaultPath);
                auto records = vault.listRecords();
                size_t success = 0;
                size_t failed = 0;

                for (const auto& r : records) {
                    bool okDec = false;
                    if (r.filename.ends_with(".kvdir")) {
                        std::string folderName = r.filename.substr(0, r.filename.size() - 6);
                        okDec = vault.decryptDirectory(r.filename, outDir / folderName, secret);
                    } else {
                        okDec = vault.decryptFile(r.filename, outDir / r.filename, secret);
                    }
                    if (okDec) success++; else failed++;
                }

                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Restored %1 record(s) successfully (%2 failed) to %3")
                    .arg(success).arg(failed).arg(QString::fromStdString(outDir.string()));
            } catch (const std::exception& error) {
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Restoration error: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void verifySelectedRecord() {
        int row = m_inventoryTable->currentRow();
        if (row < 0) {
            QMessageBox::warning(this, "Select Record", "Please select a record from the inventory table first.");
            return;
        }
        QString recName = m_inventoryTable->item(row, 0)->text();
        bool ok = false;
        QString pass = QInputDialog::getText(this, "Verify Record",
            QString("Enter passphrase for record '%1':").arg(recName),
            QLineEdit::Password, "", &ok);
        if (!ok || pass.isEmpty()) return;

        std::string secret = pass.toUtf8().toStdString();
        const auto vaultPath = toPath(m_vaultPath->text());
        const std::string filename = recName.toStdString();

        runTask(QString("Auditing HMAC for %1...").arg(recName), [vaultPath, filename, secret = std::move(secret)]() mutable {
            try {
                kvault::VaultManager vault(vaultPath);
                bool verified = vault.verifyRecord(filename, secret);
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return verified
                    ? QString("✓ Cryptographic HMAC Verification PASSED for: %1").arg(QString::fromStdString(filename))
                    : QString("✗ Cryptographic Verification FAILED (tampered ciphertext or wrong key) for: %1").arg(QString::fromStdString(filename));
            } catch (const std::exception& error) {
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Verification error: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void auditAllRecords() {
        bool ok = false;
        QString pass = QInputDialog::getText(this, "Audit All Records",
            "Enter master passphrase to audit all vault records:",
            QLineEdit::Password, "", &ok);
        if (!ok || pass.isEmpty()) return;

        std::string secret = pass.toUtf8().toStdString();
        const auto vaultPath = toPath(m_vaultPath->text());

        runTask("Auditing all records in vault...", [vaultPath, secret = std::move(secret)]() mutable {
            try {
                kvault::VaultManager vault(vaultPath);
                auto records = vault.listRecords();
                size_t passed = 0;
                size_t failed = 0;
                for (const auto& r : records) {
                    if (vault.verifyRecord(r.filename, secret)) {
                        passed++;
                    } else {
                        failed++;
                    }
                }
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Audit Complete: %1 verified OK, %2 failed.").arg(passed).arg(failed);
            } catch (const std::exception& error) {
                kvault::KeyDerivation::secureZero(secret.data(), secret.size());
                return QString("Audit error: %1").arg(QString::fromUtf8(error.what()));
            }
        });
    }

    void deleteSelectedRecord() {
        int row = m_inventoryTable->currentRow();
        if (row < 0) {
            QMessageBox::warning(this, "Select Record", "Please select a record from the inventory table first.");
            return;
        }
        QString recName = m_inventoryTable->item(row, 0)->text();
        if (QMessageBox::question(this, "Confirm Deletion",
                QString("Permanently delete vault record '%1'?").arg(recName),
                QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
            return;
        }

        const auto vaultPath = toPath(m_vaultPath->text());
        const std::string filename = recName.toStdString();

        try {
            kvault::VaultManager vault(vaultPath);
            if (vault.deleteRecord(filename)) {
                m_resultLabel->setText(QString("Deleted record: %1").arg(recName));
                refreshVaultState();
            } else {
                QMessageBox::critical(this, "Delete Failed", "Failed to delete record (it may be locked or in use).");
            }
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Delete Error", QString::fromUtf8(error.what()));
        }
    }

    void runTask(const QString& progress, std::function<QString()> task) {
        setBusy(true);
        m_resultLabel->setText(progress);
        auto* worker = QThread::create([this, task = std::move(task)]() mutable {
            const QString result = task();
            QMetaObject::invokeMethod(this, [this, result] {
                m_resultLabel->setText(result);
            }, Qt::QueuedConnection);
        });
        worker->setParent(this);
        m_worker = worker;
        connect(worker, &QThread::finished, this, [this, worker] {
            if (m_worker == worker) {
                m_worker = nullptr;
            }
            setBusy(false);
            refreshVaultState();
            worker->deleteLater();
        });
        worker->start();
    }

    void setBusy(bool busy) {
        m_vaultPath->setEnabled(!busy);
        m_initializeButton->setEnabled(!busy && !m_vaultInitialized);
        m_tabs->setEnabled(!busy);
        if (busy) {
            m_vaultState->setText("Operation in progress…");
        }
    }
};

} // namespace

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("KernelVault");
    app.setOrganizationName("KernelVault");

    MainWindow window;
    window.show();
    return app.exec();
}
