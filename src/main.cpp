/**
 * @file main.cpp
 * @brief Command-line interface entry point for kvault.
 *
 * Implements CLI argument parsing, interactive masked passphrase prompts (termios),
 * process argument scrubbing, signal handling, batch and wildcard file operations,
 * directory archiving, tabular listing, in-place cryptographic verification,
 * safe record removal, and secure multi-pass shredding.
 */

#include "VaultManager.hpp"
#include "Logger.hpp"
#include "KeyDerivation.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <string_view>
#include <vector>
#include <cstring>
#include <atomic>
#include <csignal>
#include <ctime>
#include <unistd.h>
#include <termios.h>
#include <glob.h>
#include <fnmatch.h>
#include <sys/stat.h>

namespace {

std::atomic<bool> g_interrupted{false};

void signalHandler(int sig) {
    (void)sig;
    g_interrupted.store(true);
}

void installSignalHandlers() {
    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
}

std::string promptPassphraseMasked(const std::string& prompt) {
    std::cout << prompt << std::flush;

    if (!isatty(STDIN_FILENO)) {
        std::string pass;
        if (std::getline(std::cin, pass)) {
            return pass;
        }
        return "";
    }

    struct termios oldt{}, newt{};
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        std::string pass;
        std::getline(std::cin, pass);
        return pass;
    }

    newt = oldt;
    newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string pass;
    std::getline(std::cin, pass);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    return pass;
}

std::string formatBytes(uint64_t bytes) {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    }
    char buf[32];
    if (bytes < 1024 * 1024) {
        std::snprintf(buf, sizeof(buf), "%.2f KiB", static_cast<double>(bytes) / 1024.0);
        return buf;
    }
    if (bytes < 1024ULL * 1024 * 1024) {
        std::snprintf(buf, sizeof(buf), "%.2f MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "%.2f GiB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

std::string formatMode(uint32_t mode) {
    if (mode == 0) return "---------";
    std::string s;
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

std::string formatTime(uint32_t epoch) {
    if (epoch == 0) return "N/A";
    time_t t = static_cast<time_t>(epoch);
    struct tm tm_info{};
    localtime_r(&t, &tm_info);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    return buf;
}

std::vector<std::string> expandWildcards(const std::vector<std::string>& patterns) {
    std::vector<std::string> results;
    for (const auto& pattern : patterns) {
        if (pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos) {
            glob_t globResult{};
            int ret = glob(pattern.c_str(), GLOB_TILDE | GLOB_NOCHECK, nullptr, &globResult);
            if (ret == 0) {
                for (size_t i = 0; i < globResult.gl_pathc; ++i) {
                    results.emplace_back(globResult.gl_pathv[i]);
                }
            } else {
                results.push_back(pattern);
            }
            globfree(&globResult);
        } else {
            results.push_back(pattern);
        }
    }
    return results;
}

void printBanner() {
    std::cout << "\033[1;36m"
              << "===============================================================\n"
              << "  KVAULT: High-Assurance Linux Kernel-Assisted Secure Storage  \n"
              << "===============================================================\n"
              << "\033[0m";
}

void printUsage(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << " init    --vault <path>\n"
              << "  " << prog << " encrypt --vault <path> --in <files...> [--shred] [--key <pass>]\n"
              << "  " << prog << " encrypt --vault <path> --dir <folder> [--key <pass>]\n"
              << "  " << prog << " decrypt --vault <path> --file <record> --out <dest> [--key <pass>]\n"
              << "  " << prog << " decrypt --vault <path> --file <records...> --out-dir <folder> [--key <pass>]\n"
              << "  " << prog << " decrypt --vault <path> --all --out-dir <folder> [--key <pass>]\n"
              << "  " << prog << " list    --vault <path>\n"
              << "  " << prog << " rm      --vault <path> --file <record> [--force]\n"
              << "  " << prog << " verify  --vault <path> [--file <record>] [--all] [--key <pass>]\n"
              << "  " << prog << " bench   [--size-mb <N>] [--vault <path>]\n"
              << "  " << prog << " status  --vault <path>\n\n"
              << "Commands:\n"
              << "  init           Create and format a new secure vault directory (mode 0700)\n"
              << "  encrypt        Encrypt file(s) or directories into the vault with dual keys\n"
              << "  decrypt        Verify and extract records back to original files/directories\n"
              << "  list (ls)      List all vault records with permissions, timestamps, sizes\n"
              << "  rm (delete)    Safely remove a record and its lock under advisory mutex\n"
              << "  verify (check) Cryptographic HMAC verification in-place without disk extraction\n"
              << "  bench          Run empirical performance micro-benchmark across crypto engines\n"
              << "  status         Inspect vault health, driver accelerator status, and locks\n\n"
              << "Options:\n"
              << "  --in <files...>     One or more input files or wildcards (e.g. *.pdf)\n"
              << "  --dir <folder>      Recursively pack and encrypt an entire directory tree\n"
              << "  --file <names...>   One or more vault record names or wildcards\n"
              << "  --out <dest>        Target file path for single-file decryption\n"
              << "  --out-dir <folder>  Destination directory for multi-file/batch decrypt\n"
              << "  --all               Operate on all records in vault (for decrypt or verify)\n"
              << "  --shred, --wipe     Multi-pass secure wipe of source file after encryption\n"
              << "  --force, -f         Do not prompt for confirmation when removing records\n"
              << "  --key <pass>        Passphrase (if omitted, interactive masked prompt is used)\n"
              << "  --key-stdin         Read passphrase from standard input\n"
              << "  --verbose, -v       Enable verbose debug logging\n"
              << "  --help, -h          Display this help dialog\n";
}

/**
 * @brief Configuration parameters collected from command-line arguments.
 */
struct CliOptions {
    std::string vaultPath;
    std::vector<std::string> inputFiles;
    std::string inputDir;
    std::vector<std::string> fileRecords;
    std::string outputFile;
    std::string outputDir;
    std::string key;
    bool operateAll = false;
    bool shredSource = false;
    bool forceDelete = false;
    size_t benchSizeMb = 16;
    bool verbose = false;
};

/**
 * @brief Parses command-line tokens into structured options and command name.
 *
 * @param argc Count of command-line arguments.
 * @param argv Array of argument strings.
 * @param command Output command verb.
 * @param opts Output options structure.
 * @return true if arguments were valid, false if parsing failed or help requested.
 */
static bool parseCommandLineArgs(int argc, char* argv[], std::string& command, CliOptions& opts) {
    if (argc < 2) {
        printBanner();
        printUsage(argv[0]);
        return false;
    }

    command = argv[1];
    if (command == "--help" || command == "-h") {
        printBanner();
        printUsage(argv[0]);
        return false;
    }

    int i = 2;
    while (i < argc) {
        std::string_view arg = argv[i];
        if (arg == "--vault" && i + 1 < argc) {
            opts.vaultPath = argv[++i];
        } else if (arg == "--in") {
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                opts.inputFiles.emplace_back(argv[++i]);
            }
        } else if (arg == "--dir" && i + 1 < argc) {
            opts.inputDir = argv[++i];
        } else if (arg == "--file") {
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                opts.fileRecords.emplace_back(argv[++i]);
            }
        } else if (arg == "--out" && i + 1 < argc) {
            opts.outputFile = argv[++i];
        } else if (arg == "--out-dir" && i + 1 < argc) {
            opts.outputDir = argv[++i];
        } else if (arg == "--all") {
            opts.operateAll = true;
        } else if (arg == "--shred" || arg == "--wipe") {
            opts.shredSource = true;
        } else if (arg == "--force" || arg == "-f") {
            opts.forceDelete = true;
        } else if (arg == "--key" && i + 1 < argc) {
            opts.key = argv[++i];
            std::memset(argv[i], 'x', std::strlen(argv[i]));
        } else if (arg == "--key-stdin") {
            if (!std::getline(std::cin, opts.key)) {
                opts.key = "";
            }
        } else if (arg == "--size-mb" && i + 1 < argc) {
            opts.benchSizeMb = std::stoul(argv[++i]);
        } else if (arg == "--verbose" || arg == "-v") {
            opts.verbose = true;
        }
        ++i;
    }

    if (opts.key.empty()) {
        const char* envKey = std::getenv("KVAULT_KEY");
        if (envKey && std::strlen(envKey) > 0) {
            opts.key = envKey;
        }
    }

    if (opts.verbose) {
        kvault::Logger::setMinLevel(kvault::Logger::Level::Debug);
    }

    return true;
}

/**
 * @brief Executes the vault initialization command.
 *
 * @param vault VaultManager reference for storage operations.
 * @return int Exit code (0 for success, 1 for failure).
 */
static int executeInit(kvault::VaultManager& vault) {
    printBanner();
    return vault.initializeVault() ? 0 : 1;
}

/**
 * @brief Executes file and directory encryption operations.
 *
 * @param vault VaultManager reference for storage operations.
 * @param opts Options containing input file paths, directory targets, and passphrase.
 * @return int Exit code (0 for success, non-zero on error).
 */
static int executeEncrypt(kvault::VaultManager& vault, CliOptions& opts) {
    printBanner();

    if (opts.inputFiles.empty() && opts.inputDir.empty()) {
        kvault::Logger::error("Missing input: Specify --in <file...> or --dir <folder>");
        return 1;
    }

    // Prompt for passphrase if not supplied via CLI or environment
    if (opts.key.empty()) {
        opts.key = promptPassphraseMasked("Enter vault passphrase: ");
        if (opts.key.empty()) {
            kvault::Logger::error("Passphrase cannot be empty");
            return 1;
        }
        std::string confirm = promptPassphraseMasked("Confirm vault passphrase: ");
        if (opts.key != confirm) {
            kvault::Logger::error("Passphrase confirmation mismatch. Encryption aborted.");
            kvault::KeyDerivation::secureZero(opts.key.data(), opts.key.size());
            kvault::KeyDerivation::secureZero(confirm.data(), confirm.size());
            return 1;
        }
        kvault::KeyDerivation::secureZero(confirm.data(), confirm.size());
    }

    int exitCode = 0;

    // Encrypt recursive directory tree if specified
    if (!opts.inputDir.empty()) {
        std::cout << "[*] Encrypting directory hierarchy: " << opts.inputDir << "\n";
        if (!vault.encryptDirectory(opts.inputDir, opts.key)) {
            exitCode = 1;
        }
    }

    // Encrypt individual files / wildcards
    if (!opts.inputFiles.empty()) {
        std::vector<std::string> expandedFiles = expandWildcards(opts.inputFiles);
        if (expandedFiles.empty()) {
            kvault::Logger::error("No files matched input specification");
            return 1;
        }

        size_t successCount = 0;
        size_t failCount = 0;

        for (const auto& f : expandedFiles) {
            if (g_interrupted.load()) {
                kvault::Logger::warn("Operation interrupted by user signal.");
                return 130;
            }

            std::error_code ec;
            if (std::filesystem::is_directory(f, ec)) {
                std::cout << "[*] Encrypting directory: " << f << "\n";
                if (vault.encryptDirectory(f, opts.key)) {
                    successCount++;
                } else {
                    failCount++;
                }
            } else {
                std::cout << "[*] Encrypting file: " << f << "\n";
                if (vault.encryptFile(f, opts.key)) {
                    successCount++;
                    if (opts.shredSource) {
                        std::cout << "    [+] Securely shredding source file: " << f << "\n";
                        kvault::VaultManager::shredFile(f);
                    }
                } else {
                    failCount++;
                }
            }
        }

        std::cout << "\nBatch Encryption Complete: " << successCount << " succeeded, "
                  << failCount << " failed.\n";
        if (failCount > 0) exitCode = 1;
    }

    return exitCode;
}

/**
 * @brief Resolves target record names for decryption based on filters and wildcards.
 *
 * @param vault VaultManager reference to query vault records.
 * @param opts User CLI options.
 * @param targets Output list of matched record names.
 * @return true if valid targets were found, false otherwise.
 */
static bool resolveDecryptTargets(kvault::VaultManager& vault, const CliOptions& opts, std::vector<std::string>& targets) {
    if (opts.operateAll) {
        auto records = vault.listRecords();
        for (const auto& r : records) {
            targets.push_back(r.filename);
        }
        if (targets.empty()) {
            kvault::Logger::warn("No records found in vault to decrypt.");
            return false;
        }
    } else if (!opts.fileRecords.empty()) {
        auto records = vault.listRecords();
        for (const auto& pat : opts.fileRecords) {
            if (pat.find('*') != std::string::npos || pat.find('?') != std::string::npos) {
                for (const auto& r : records) {
                    if (fnmatch(pat.c_str(), r.filename.c_str(), 0) == 0) {
                        targets.push_back(r.filename);
                    }
                }
            } else {
                targets.push_back(pat);
            }
        }
    } else {
        kvault::Logger::error("Missing decrypt target: specify --file <record...> or --all");
        return false;
    }
    return true;
}

/**
 * @brief Executes record decryption and directory restoration operations.
 *
 * @param vault VaultManager reference for storage operations.
 * @param opts Options containing record names, destination paths, and passphrase.
 * @return int Exit code (0 for success, non-zero on error).
 */
static int executeDecrypt(kvault::VaultManager& vault, CliOptions& opts) {
    printBanner();

    std::vector<std::string> targets;
    if (!resolveDecryptTargets(vault, opts, targets)) {
        return opts.operateAll ? 0 : 1;
    }

    // Validate destination parameters
    if (targets.size() > 1 || !opts.outputDir.empty() || opts.operateAll) {
        if (opts.outputDir.empty() && !opts.outputFile.empty()) {
            opts.outputDir = opts.outputFile;
        }
        if (opts.outputDir.empty()) {
            kvault::Logger::error("Batch decryption requires destination directory: --out-dir <folder>");
            return 1;
        }
    } else if (opts.outputFile.empty()) {
        kvault::Logger::error("Missing required parameter: --out <destination> or --out-dir <folder>");
        return 1;
    }

    // Prompt for passphrase if needed
    if (opts.key.empty()) {
        opts.key = promptPassphraseMasked("Enter vault passphrase: ");
        if (opts.key.empty()) {
            kvault::Logger::error("Passphrase cannot be empty");
            return 1;
        }
    }

    size_t successCount = 0;
    size_t failCount = 0;

    for (const auto& rec : targets) {
        if (g_interrupted.load()) {
            kvault::Logger::warn("Operation interrupted by user signal.");
            return 130;
        }

        const bool isDirArchive = rec.ends_with(".kvdir");
        std::filesystem::path destPath;

        if (!opts.outputDir.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(opts.outputDir, ec);
            if (isDirArchive) {
                std::string folderName = rec.substr(0, rec.size() - 6);
                destPath = std::filesystem::path(opts.outputDir) / folderName;
            } else {
                destPath = std::filesystem::path(opts.outputDir) / rec;
            }
        } else {
            destPath = opts.outputFile;
        }

        if (isDirArchive) {
            std::cout << "[*] Restoring directory archive: " << rec << " -> " << destPath.string() << "\n";
            if (vault.decryptDirectory(rec, destPath, opts.key)) {
                successCount++;
            } else {
                failCount++;
            }
        } else {
            std::cout << "[*] Restoring record: " << rec << " -> " << destPath.string() << "\n";
            if (vault.decryptFile(rec, destPath, opts.key)) {
                successCount++;
            } else {
                failCount++;
            }
        }
    }

    if (targets.size() > 1) {
        std::cout << "\nBatch Decryption Complete: " << successCount << " restored, "
                  << failCount << " failed.\n";
    }
    return (failCount > 0) ? 1 : 0;
}

/**
 * @brief Formats and displays an inventory table of all records in the vault.
 *
 * @param vault VaultManager reference for storage operations.
 * @return int Exit code (always 0).
 */
static int executeList(kvault::VaultManager& vault) {
    printBanner();
    auto records = vault.listRecords();

    std::cout << "\n\033[1;37m" << std::left
              << std::setw(28) << "RECORD NAME"
              << std::setw(6)  << "VER"
              << std::setw(14) << "ORIGINAL"
              << std::setw(14) << "STORED"
              << std::setw(12) << "MODE"
              << std::setw(21) << "MODIFIED"
              << std::setw(8)  << "STATUS"
              << "\033[0m\n";
    std::cout << std::string(103, '-') << "\n";

    uint64_t totalPlain = 0;
    uint64_t totalEnc = 0;

    for (const auto& r : records) {
        totalPlain += r.original_size;
        totalEnc += r.payload_size;

        std::string statusStr = r.is_locked ? "\033[33mLOCKED\033[0m" : "\033[32mREADY\033[0m";

        std::cout << std::left
                  << std::setw(28) << (r.filename.size() > 27 ? r.filename.substr(0, 24) + "..." : r.filename)
                  << std::setw(6)  << ("v" + std::to_string(r.version))
                  << std::setw(14) << formatBytes(r.original_size)
                  << std::setw(14) << formatBytes(r.payload_size)
                  << std::setw(12) << formatMode(r.posix_mode)
                  << std::setw(21) << formatTime(r.mtime_epoch)
                  << statusStr
                  << "\n";
    }

    std::cout << std::string(103, '-') << "\n";
    std::cout << "Total: " << records.size() << " record(s) | "
              << "Plaintext: " << formatBytes(totalPlain) << " | "
              << "Stored Vault Footprint: " << formatBytes(totalEnc) << "\n\n";

    return 0;
}

/**
 * @brief Removes specified records from the vault.
 *
 * @param vault VaultManager reference for storage operations.
 * @param opts Options containing record targets and confirmation flags.
 * @return int Exit code (0 for success, non-zero if any deletion failed).
 */
static int executeRemove(kvault::VaultManager& vault, const CliOptions& opts) {
    printBanner();
    if (opts.fileRecords.empty()) {
        kvault::Logger::error("Missing required parameter: --file <record>");
        return 1;
    }

    int exitCode = 0;
    for (const auto& rec : opts.fileRecords) {
        if (!opts.forceDelete) {
            std::cout << "Are you sure you want to permanently delete vault record '" << rec << "'? [y/N]: ";
            std::string confirm;
            if (!std::getline(std::cin, confirm) || (confirm != "y" && confirm != "Y")) {
                std::cout << "Deletion cancelled for: " << rec << "\n";
                continue;
            }
        }

        if (!vault.deleteRecord(rec)) {
            exitCode = 1;
        } else {
            std::cout << "\033[32m[+] Successfully deleted record: " << rec << "\033[0m\n";
        }
    }
    return exitCode;
}

/**
 * @brief Verifies cryptographic HMAC integrity for vault records.
 *
 * @param vault VaultManager reference for storage operations.
 * @param opts Options containing record targets and verification passphrase.
 * @return int Exit code (0 for success, non-zero if HMAC failed).
 */
static int executeVerify(kvault::VaultManager& vault, CliOptions& opts) {
    printBanner();

    std::vector<std::string> targets;
    if (opts.operateAll) {
        auto records = vault.listRecords();
        for (const auto& r : records) targets.push_back(r.filename);
    } else if (!opts.fileRecords.empty()) {
        targets = opts.fileRecords;
    } else {
        kvault::Logger::error("Missing verify target: specify --file <record> or --all");
        return 1;
    }

    if (opts.key.empty()) {
        opts.key = promptPassphraseMasked("Enter vault passphrase for verification: ");
        if (opts.key.empty()) {
            kvault::Logger::error("Passphrase cannot be empty");
            return 1;
        }
    }

    size_t passCount = 0;
    size_t failCount = 0;

    for (const auto& rec : targets) {
        std::cout << "[*] Auditing cryptographic HMAC for record: " << rec << " ... ";
        if (vault.verifyRecord(rec, opts.key)) {
            std::cout << "\033[32m[VERIFIED OK]\033[0m\n";
            passCount++;
        } else {
            std::cout << "\033[31m[FAILED / TAMPERED]\033[0m\n";
            failCount++;
        }
    }

    std::cout << "\nVerification Audit Complete: " << passCount << " passed, "
              << failCount << " failed.\n";
    return (failCount > 0) ? 1 : 0;
}

/**
 * @brief Inspects and displays diagnostic and health metrics for the vault.
 *
 * @param vault VaultManager reference for storage operations.
 * @return int Exit code (always 0).
 */
static int executeStatus(kvault::VaultManager& vault) {
    printBanner();
    auto status = vault.inspectStatus();
    std::cout << "\nVault Diagnostics for: " << status.vault_path << "\n";
    std::cout << "  - Initialized:              " << (status.is_initialized ? "YES" : "NO") << "\n";
    std::cout << "  - Stored Records:           " << status.file_count << "\n";
    std::cout << "  - Total Encrypted Size:     " << formatBytes(status.total_vault_bytes) << " (" << status.total_vault_bytes << " bytes)\n";
    std::cout << "  - Kernel Driver Node:       "
              << (status.kernel_driver_available ? "\033[32mACTIVE (/dev/kvault)\033[0m" : "\033[33mINACTIVE (Software Fallback)\033[0m")
              << "\n";

    if (status.kernel_driver_available) {
        std::cout << "  - Driver Protocol Version:  0x" << std::hex << status.kernel_driver_version << std::dec << "\n";
        std::cout << "  - Lifetime Transformed:     " << formatBytes(status.kernel_bytes_transformed) << " (" << status.kernel_bytes_transformed << " bytes)\n";
    }

    if (status.stale_locks_pruned > 0) {
        std::cout << "  - Garbage-Collected Locks:  " << status.stale_locks_pruned << " abandoned lock files pruned\n";
    }

    if (!status.stored_files.empty()) {
        std::cout << "\nFiles in Vault:\n";
        for (const auto& f : status.stored_files) {
            std::cout << "    [+] " << f << "\n";
        }
    }
    std::cout << "\n";
    return 0;
}

/**
 * @brief Runs cryptographic performance benchmarks on the vault algorithms.
 *
 * @param vault VaultManager reference for benchmarking operations.
 * @param opts Options containing benchmark size configuration.
 * @return int Exit code (always 0).
 */
static int executeBenchmark(kvault::VaultManager& vault, const CliOptions& opts) {
    printBanner();
    std::cout << "\n\033[1m[*] Running Cryptographic Performance Benchmark ("
              << opts.benchSizeMb << " MiB Workload)...\033[0m\n\n";

    auto metrics = vault.runBenchmark(opts.benchSizeMb * 1024 * 1024);

    std::cout << std::left
              << std::setw(26) << "Operation"
              << std::setw(38) << "Workload / Details"
              << std::setw(14) << "Time (ms)"
              << std::setw(18) << "Throughput"
              << std::setw(30) << "Engine / Backend"
              << "\n";
    std::cout << std::string(126, '=') << "\n";

    for (const auto& m : metrics) {
        std::cout << std::left
                  << std::setw(26) << m.operation
                  << std::setw(38) << m.detail
                  << std::setw(14) << std::fixed << std::setprecision(2) << m.elapsed_ms;

        if (m.operation.find("PBKDF2") != std::string::npos) {
            std::string iterStr = std::to_string(static_cast<uint64_t>(m.throughput_mb_s)) + " iter/s";
            std::cout << std::setw(18) << iterStr;
        } else {
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(2) << m.throughput_mb_s << " MB/s";
            std::cout << std::setw(18) << ss.str();
        }

        std::cout << std::setw(30) << m.backend << "\n";
    }
    std::cout << std::string(120, '=') << "\n\n";
    return 0;
}

} // namespace

/**
 * @brief Main entrypoint for the KernelVault command-line interface.
 *
 * @param argc Number of command-line arguments provided in argv.
 * @param argv Array of null-terminated command-line argument strings.
 * @return int Process exit code (0 for success, non-zero for operational errors).
 *
 * @details Validates and executes vault commands ('init', 'encrypt', 'decrypt',
 * 'list', 'verify', 'rm', 'status', 'bench'). Handles batch files, directory archiving,
 * and immediate memory scrubbing of credentials from argv.
 */
int main(int argc, char* argv[]) {
    // Register OS signal handlers for graceful cancellation
    installSignalHandlers();

    // Parse options from command-line arguments
    std::string command;
    CliOptions opts;
    if (!parseCommandLineArgs(argc, argv, command, opts)) {
        return (argc >= 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) ? 0 : 1;
    }

    // Benchmark mode defaults to current working directory if vaultPath is omitted
    if ((command == "bench" || command == "benchmark") && opts.vaultPath.empty()) {
        opts.vaultPath = ".";
    } else if (opts.vaultPath.empty()) {
        kvault::Logger::error("Missing required parameter: --vault <path>");
        return 1;
    }

    // Initialize vault manager and dispatch command
    kvault::VaultManager vault(opts.vaultPath);
    int exitCode = 0;

    if (command == "init") {
        exitCode = executeInit(vault);
    } else if (command == "encrypt") {
        exitCode = executeEncrypt(vault, opts);
    } else if (command == "decrypt") {
        exitCode = executeDecrypt(vault, opts);
    } else if (command == "list" || command == "ls") {
        exitCode = executeList(vault);
    } else if (command == "rm" || command == "delete") {
        exitCode = executeRemove(vault, opts);
    } else if (command == "verify" || command == "check") {
        exitCode = executeVerify(vault, opts);
    } else if (command == "status") {
        exitCode = executeStatus(vault);
    } else if (command == "bench" || command == "benchmark") {
        exitCode = executeBenchmark(vault, opts);
    } else {
        kvault::Logger::error("Unknown command: " + command);
        printUsage(argv[0]);
        exitCode = 1;
    }

    // Securely wipe sensitive passphrase from process memory
    if (!opts.key.empty()) {
        kvault::KeyDerivation::secureZero(opts.key.data(), opts.key.size());
    }

    return exitCode;
}
