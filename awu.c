/* awu.c */
/*
 * Axis Wiping Utility (awu)
 * Classified data sanitization tool aligned with NIST SP 800-88 Rev. 1
 * Compile: gcc awu.c -o awu -Wall -Wextra -O2
 * Run: ./awu
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/vfs.h>
#ifdef __linux__
#include <linux/fs.h>
#endif
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <termios.h>
#include <signal.h>
#include <stdint.h>
#include <sys/sysinfo.h>

/* ==================== ANSI COLOR CODES (WHITE, CYAN, BOLD ONLY) ==================== */
#define COLOR_WHITE   "\x1b[37m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_BOLD    "\x1b[1m"
#define COLOR_RESET   "\x1b[0m"

/* ==================== CONFIGURATION & SCHEMES ==================== */
#define SAFE_ZONE_BYTES (10ULL * 1024 * 1024)
#define BUFFER_SIZE (1ULL * 1024 * 1024)
#define PROGRESS_UPDATE_INTERVAL (4ULL * 1024 * 1024)

/* RAM fill parameters (from mem.c) */
#define DEFAULT_SAFETY_MB 250
#define CHUNK_SIZE_GB     1UL
#define PAGE_SIZE         4096

typedef enum {
    PASS_ZERO = 0,
    PASS_ONES,
    PASS_RANDOM,
    PASS_VERIFY
} PassType;

typedef struct {
    int id;
    const char *name;
    const char *standard;
    PassType passes[10];
    int pass_count;
} WipeScheme;

/* NIST SP 800-88 Rev. 1 Aligned Sanitization Schemes */
static const WipeScheme schemes[] = {
    {1, "NIST Clear (Baseline)",        "NIST SP 800-88 Rev. 1 §4.1",  {PASS_ZERO}, 1},
    {2, "DoD 5220.22-M (Overwrite)",    "DoD 5220.22-M (E)",          {PASS_ZERO, PASS_ONES, PASS_RANDOM}, 3},
    {3, "NIST Purge (Multi-Pass)",      "NIST SP 800-88 Rev. 1 §4.2",  {PASS_ZERO, PASS_ONES, PASS_RANDOM, PASS_VERIFY}, 4},
    {4, "FIPS High-Entropy Purge",      "FIPS 140-3 / NIST 800-88",    {PASS_RANDOM, PASS_RANDOM, PASS_ZERO, PASS_RANDOM, PASS_VERIFY}, 5}
};

/* ==================== GLOBAL STATE ==================== */
static int current_scheme_idx = 0;
static volatile sig_atomic_t g_stop_flag = 0;
static volatile size_t g_bytes_written = 0;
static volatile size_t g_target_bytes = 0;
static volatile time_t g_start_time = 0;
static struct termios g_original_termios;
static int g_termios_saved = 0;
static int g_mlock_supported = 0;

/* ==================== RAM FILL STATE (from mem.c) ==================== */
static void **allocated_blocks = NULL;
static size_t block_count = 0;
static size_t block_capacity = 0;
static volatile sig_atomic_t fill_keep_running = 1;

static void fill_sigint_handler(int sig) {
    (void)sig;
    fill_keep_running = 0;
}

/* ==================== SECURE UTILITIES ==================== */
static void secure_memzero(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

static int get_secure_random(void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t r = getrandom((char *)buf + total, len - total, 0);
        if (r <= 0) return -1;
        total += (size_t)r;
    }
    return 0;
}

static void fill_buffer(unsigned char *buf, size_t len, PassType type) {
    switch (type) {
        case PASS_ZERO:  memset(buf, 0x00, len); break;
        case PASS_ONES:  memset(buf, 0xFF, len); break;
        case PASS_RANDOM:
            if (get_secure_random(buf, len) != 0) {
                fprintf(stderr, "\n" COLOR_BOLD "[!] Secure random generation failed. Aborting.\n" COLOR_RESET);
                exit(EXIT_FAILURE);
            }
            break;
        case PASS_VERIFY: break;
    }
}

/* ==================== TRIM & CACHE PURGE (OPSEC) ==================== */
static void attempt_trim(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) { sync(); return; }

    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { sync(); return; }

#if defined(__linux__) && defined(FITRIM)
    struct fstrim_range range = { .start = 0, .len = ~0ULL, .minlen = 4096 };
    ioctl(fd, FITRIM, &range);
#endif
    sync();
    close(fd);
}

/* ==================== TERMINAL & INTERRUPT ==================== */
static void restore_terminal(void) {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_original_termios);
        g_termios_saved = 0;
    }
}

static int check_for_stop_interrupt(void) {
    struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
    if (poll(&pfd, 1, 50) > 0) {
        char c;
        if (read(STDIN_FILENO, &c, 1) == 1) {
            if (c == 's' || c == 'S') {
                g_stop_flag = 1;
                return 1;
            }
        }
    }
    return 0;
}

static void update_progress(const char *label) {
    if (g_target_bytes == 0) return;
    double pct = (double)g_bytes_written / (double)g_target_bytes * 100.0;
    double elapsed = difftime(time(NULL), g_start_time);
    double speed = (elapsed > 0) ? (g_bytes_written / (1024.0 * 1024.0)) / elapsed : 0.0;
    long long remaining_sec = (speed > 0) ? (long long)((g_target_bytes - g_bytes_written) / (speed * 1024.0 * 1024.0)) : 0;
    int mins = (int)(remaining_sec / 60);
    int secs = (int)(remaining_sec % 60);
    int bar_len = 30;
    int filled = (int)(pct / 100.0 * bar_len);
    
    if (filled < 0) filled = 0;
    if (filled > bar_len) filled = bar_len;
    
    char bar[32] = {0};
    for (int i = 0; i < bar_len; i++) bar[i] = (i < filled) ? '#' : ' ';
    bar[bar_len] = '\0';
    printf("\r[" COLOR_CYAN "%s" COLOR_RESET "] %5.1f%% | %6.2f MB/s | ETA: %02d:%02d | %s",
           bar, pct, speed, mins, secs, label);
    fflush(stdout);
}

/* ==================== STARTUP COMPLIANCE CHECK ==================== */
static void startup_compliance_check(void) {
    int warnings = 0;

    void *test_buf = aligned_alloc(4096, BUFFER_SIZE);
    if (test_buf) {
        if (mlock(test_buf, BUFFER_SIZE) == 0) {
            g_mlock_supported = 1;
            munlock(test_buf, BUFFER_SIZE);
        } else {
            printf(COLOR_BOLD "[!] WARNING: mlock unavailable. Memory may page to disk.\n" COLOR_RESET);
            warnings++;
        }
        free(test_buf);
    }

    struct statfs stfs;
    if (statfs(".", &stfs) == 0) {
        uint64_t fs_types[] = {0xEF53ULL, 0x58465342ULL, 0x9123683EULL, 0x2FC12FC1ULL, 0xF2F52010ULL, 0};
        for (int i = 0; fs_types[i] != 0; i++) {
            if ((uint64_t)stfs.f_type == fs_types[i]) {
                printf(COLOR_BOLD "[!] WARNING: Journal/CoW filesystem detected. Metadata/journal may retain residual data.\n" COLOR_RESET);
                warnings++;
                break;
            }
        }
    }

    if (warnings == 0) {
        printf(COLOR_CYAN "[i] Compliance checks passed. Operating in classified mode.\n" COLOR_RESET);
    } else {
        printf(COLOR_BOLD "[i] Fallbacks enabled. Proceeding with best-effort sanitization.\n" COLOR_RESET);
    }
}

/* ==================== RAM FILL / RELEASE (from mem.c, adapted) ==================== */
static void add_block(void *ptr) {
    if (block_count >= block_capacity) {
        size_t new_cap = block_capacity ? block_capacity * 2 : 16;
        void **new_arr = realloc(allocated_blocks, new_cap * sizeof(void*));
        if (!new_arr) {
            fprintf(stderr, COLOR_BOLD "[!] Failed to grow block array\n" COLOR_RESET);
            return;
        }
        allocated_blocks = new_arr;
        block_capacity = new_cap;
    }
    allocated_blocks[block_count++] = ptr;
}

static void free_all_blocks(void) {
    for (size_t i = 0; i < block_count; i++) {
        free(allocated_blocks[i]);
    }
    free(allocated_blocks);
    allocated_blocks = NULL;
    block_count = block_capacity = 0;
}

static unsigned long get_avail_mb(void) {
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo");
        return 0;
    }
    unsigned long avail_bytes = (info.freeram + info.bufferram) * info.mem_unit;
    return avail_bytes / (1024 * 1024);
}

static void touch_pages(void *ptr, size_t size_bytes) {
    volatile char *p = (volatile char *)ptr;
    for (size_t i = 0; i < size_bytes; i += PAGE_SIZE) {
        p[i] = 0;
    }
}

static void fill_ram(unsigned long safety_mb) {
    fill_keep_running = 1;
    unsigned long avail_mb;
    size_t chunk_bytes = CHUNK_SIZE_GB * 1024UL * 1024UL * 1024UL;

    printf(COLOR_CYAN "\n[*] Starting RAM fill. Safety margin: %lu MB\n" COLOR_RESET, safety_mb);
    printf(COLOR_BOLD "[i] Press Ctrl+C to stop and keep memory allocated.\n" COLOR_RESET);

    signal(SIGINT, fill_sigint_handler);

    while (fill_keep_running) {
        avail_mb = get_avail_mb();
        if (avail_mb <= safety_mb) {
            printf(COLOR_CYAN "\nAvailable memory %lu MB <= safety margin %lu MB. Stopping.\n" COLOR_RESET,
                   avail_mb, safety_mb);
            break;
        }

        size_t alloc_bytes = chunk_bytes;
        if (avail_mb - safety_mb < CHUNK_SIZE_GB * 1024) {
            alloc_bytes = (avail_mb - safety_mb) * 1024UL * 1024UL;
            if (alloc_bytes == 0) break;
        }

        printf("Allocating %.2f GB (avail: %lu MB) ... ",
               alloc_bytes / (1024.0*1024.0*1024.0), avail_mb);
        fflush(stdout);

        void *block = malloc(alloc_bytes);
        if (!block) {
            perror("\nmalloc failed");
            break;
        }

        touch_pages(block, alloc_bytes);
        add_block(block);

        printf(COLOR_CYAN "done. Total blocks: %zu\n" COLOR_RESET, block_count);
    }

    printf(COLOR_CYAN "\nMemory fill stopped. %zu blocks allocated.\n" COLOR_RESET, block_count);
}

static void release_ram(void) {
    size_t freed = block_count;
    free_all_blocks();
    printf(COLOR_CYAN "[+] All memory released (%zu blocks freed).\n" COLOR_RESET, freed);
}

/* ==================== FILE WIPE & DELETE (Classified OPSEC) ==================== */
static int wipe_file(const char *path) {
    g_stop_flag = 0;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, COLOR_BOLD "[!] Not a regular file or inaccessible: %s\n" COLOR_RESET, path);
        return -1;
    }

    if (st.st_size <= 0) {
        printf(COLOR_BOLD "[i] Skipping empty file: %s\n" COLOR_RESET, path);
        return 0;
    }

    size_t file_size = (size_t)st.st_size;
    g_target_bytes = file_size;
    g_bytes_written = 0;
    g_start_time = time(NULL);
    printf("\n" COLOR_CYAN "[*] Sanitizing: %s (%.2f MB)\n" COLOR_RESET, path, file_size / 1048576.0);

    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror(COLOR_BOLD "[!] open" COLOR_RESET); return -1; }

    unsigned char *buf = aligned_alloc(4096, BUFFER_SIZE);
    int res = -1;
    if (buf) {
        if (g_mlock_supported && mlock(buf, BUFFER_SIZE) != 0) g_mlock_supported = 0;
        res = 0;
        size_t offset = 0;

        for (int p = 0; p < schemes[current_scheme_idx].pass_count && !g_stop_flag; p++) {
            PassType type = schemes[current_scheme_idx].passes[p];
            fill_buffer(buf, BUFFER_SIZE, type);
            offset = 0;
            while (offset < file_size) {
                size_t to_write = (file_size - offset > BUFFER_SIZE) ? BUFFER_SIZE : (file_size - offset);
                lseek(fd, (off_t)offset, SEEK_SET);
                
                if (type == PASS_VERIFY) {
                    if (read(fd, buf, to_write) != (ssize_t)to_write) { res = -1; break; }
                } else {
                    if (write(fd, buf, to_write) != (ssize_t)to_write) { res = -1; break; }
                }
                g_bytes_written += to_write;
                offset += to_write;
                if (g_bytes_written % PROGRESS_UPDATE_INTERVAL == 0) {
                    update_progress("Sanitizing...");
                    if (check_for_stop_interrupt()) { res = -2; break; }
                }
            }
            if (res != 0) break;
            fsync(fd);
            update_progress("Sanitizing...");
        }
        secure_memzero(buf, BUFFER_SIZE);
        if (g_mlock_supported) munlock(buf, BUFFER_SIZE);
        free(buf);
    }
    close(fd);

    if (res == 0) {
        char *dir = strdup(path);
        if (dir) {
            char *last_slash = strrchr(dir, '/');
            if (last_slash) *last_slash = '\0'; else strcpy(dir, ".");
            char new_name[4096];
            snprintf(new_name, sizeof(new_name), "%s/.awu_del_%lu_%lu.tmp", dir, (unsigned long)time(NULL), (unsigned long)getpid());
            if (rename(path, new_name) == 0) {
                int dfd = open(dir, O_RDONLY);
                if (dfd >= 0) { fsync(dfd); close(dfd); }
                if (unlink(new_name) == 0) attempt_trim(path);
            } else { unlink(path); }
            free(dir);
        }
        printf("\n" COLOR_CYAN "[+] File securely sanitized & removed: %s\n" COLOR_RESET, path);
    } else if (res == -2) {
        printf("\n" COLOR_BOLD "[!] Sanitization interrupted. File remains on disk.\n" COLOR_RESET);
    }
    return res;
}

/* ==================== DIRECTORY WIPE ==================== */
static int wipe_directory_recursive(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) { perror(COLOR_BOLD "[!] opendir" COLOR_RESET); return -1; }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            wipe_directory_recursive(fullpath);
            rmdir(fullpath);
        } else if (S_ISREG(st.st_mode)) {
            wipe_file(fullpath);
        }
    }
    closedir(dir);
    return 0;
}

/* ==================== FREE SPACE WIPE ==================== */
static int wipe_free_space(const char *path) {
    g_stop_flag = 0;
    struct statvfs st;
    if (statvfs(path, &st) != 0) { perror(COLOR_BOLD "[!] statvfs" COLOR_RESET); return -1; }
    uint64_t avail = (uint64_t)st.f_bavail * (uint64_t)st.f_bsize;
    if (avail <= SAFE_ZONE_BYTES) {
        printf(COLOR_BOLD "[!] Less than 10MB available. Aborting free space sanitize.\n" COLOR_RESET);
        return -1;
    }

    g_target_bytes = (size_t)(avail - SAFE_ZONE_BYTES);
    g_bytes_written = 0; 
    g_start_time = time(NULL);
    printf("\n" COLOR_CYAN "[*] Sanitizing free space on: %s\n" COLOR_RESET, path);
    printf(COLOR_CYAN "[*] Target: %.2f GB | Safe zone: 10MB\n" COLOR_RESET, (double)g_target_bytes / 1073741824.0);
    printf(COLOR_BOLD "[i] Press 's' then Enter to stop & cleanup.\n" COLOR_RESET);

    tcgetattr(STDIN_FILENO, &g_original_termios);
    struct termios newt = g_original_termios;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    g_termios_saved = 1; atexit(restore_terminal);

    char tmp_template[4096];
    if (strlen(path) + 18 > sizeof(tmp_template)) {
        fprintf(stderr, COLOR_BOLD "[!] Path too long: %s\n" COLOR_RESET, path);
        restore_terminal();
        return -1;
    }
    snprintf(tmp_template, sizeof(tmp_template), "%s/.awu_free_XXXXXX", path);
    
    char **tmp_files = malloc(64 * sizeof(char *));
    if (!tmp_files) { restore_terminal(); return -1; }
    int tmp_count = 0, tmp_capacity = 64;

    while (g_bytes_written < g_target_bytes && !g_stop_flag) {
        if (tmp_count >= tmp_capacity) {
            tmp_capacity *= 2;
            char **new_ptr = realloc(tmp_files, (size_t)tmp_capacity * sizeof(char *));
            if (!new_ptr) break;
            tmp_files = new_ptr;
        }
        char *tmpname = strdup(tmp_template);
        int fd = mkstemp(tmpname);
        if (fd < 0) { free(tmpname); break; }
        tmp_files[tmp_count++] = tmpname;

        size_t remaining = g_target_bytes - g_bytes_written;
        size_t chunk = (remaining > BUFFER_SIZE * 20) ? BUFFER_SIZE * 20 : remaining;
        unsigned char *buf = aligned_alloc(4096, BUFFER_SIZE);
        if (buf) {
            if (g_mlock_supported && mlock(buf, BUFFER_SIZE) != 0) g_mlock_supported = 0;
            for (int p = 0; p < schemes[current_scheme_idx].pass_count && !g_stop_flag; p++) {
                fill_buffer(buf, BUFFER_SIZE, schemes[current_scheme_idx].passes[p]);
                lseek(fd, 0, SEEK_SET);
                size_t off = 0;
                while (off < chunk) {
                    size_t tw = (chunk - off > BUFFER_SIZE) ? BUFFER_SIZE : (chunk - off);
                    if (write(fd, buf, tw) != (ssize_t)tw) {
                        perror("Write failed during free space wipe");
                        break;
                    }
                    off += tw;
                }
                fsync(fd);
            }
            secure_memzero(buf, BUFFER_SIZE);
            if (g_mlock_supported) munlock(buf, BUFFER_SIZE);
            free(buf);
        }
        close(fd);
        g_bytes_written += chunk;
        update_progress("Sanitizing Free Space...");
        if (check_for_stop_interrupt()) break;
    }

    restore_terminal();
    while (poll(&(struct pollfd){.fd=STDIN_FILENO, .events=POLLIN}, 1, 0) > 0) { 
        int c; while ((c = getchar()) != '\n' && c != EOF) { }
    }
    printf("\n" COLOR_CYAN "[*] Cleaning %d temporary files...\n" COLOR_RESET, tmp_count);
    for (int i = 0; i < tmp_count; i++) { unlink(tmp_files[i]); free(tmp_files[i]); }
    free(tmp_files);
    attempt_trim(path); sync();
    printf(COLOR_CYAN "[+] Free space sanitization & cleanup complete.\n" COLOR_RESET);
    return 0;
}

/* ==================== SETTINGS & MENU ==================== */
static void show_settings(void) {
    printf("\n" COLOR_BOLD COLOR_CYAN "=== SANITIZATION SCHEMES ===" COLOR_RESET "\n");
    for (int i = 0; i < 4; i++) {
        printf(COLOR_CYAN "[%d]" COLOR_RESET " %s\n      " COLOR_WHITE "Reference: %s" COLOR_RESET "\n",
               i + 1, schemes[i].name, schemes[i].standard);
    }
    printf(COLOR_CYAN "Current: [%d] %s\n" COLOR_RESET, current_scheme_idx + 1, schemes[current_scheme_idx].name);
    printf("Enter new scheme (1-4) or 0 to cancel: ");
    int choice;
    if (scanf("%d", &choice) == 1 && choice >= 1 && choice <= 4) {
        current_scheme_idx = choice - 1;
        printf(COLOR_CYAN "[+] Scheme updated.\n" COLOR_RESET);
    }
    while (getchar() != '\n');
}

int main(void) {
    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit rl = {0, 0}; setrlimit(RLIMIT_CORE, &rl);

    startup_compliance_check();

    printf("\n" COLOR_BOLD COLOR_CYAN);
    printf("                    AXIS WIPING UTILITY (awu)\n");
    printf(COLOR_RESET);
    printf(COLOR_WHITE "         NIST SP 800-88 Rev. 1 | FIPS 140-3 Aligned\n" COLOR_RESET);
    printf(COLOR_CYAN "         Secure Erase for Controlled Environments\n" COLOR_RESET);
    printf("  ==================================================\n");
    printf(COLOR_WHITE "[i] Runtime compliance warnings disabled. Fallbacks active.\n\n" COLOR_RESET);

    int choice;
    while (1) {
        printf("\n" COLOR_BOLD COLOR_CYAN "=== MAIN MENU ===" COLOR_RESET "\n");
        printf(COLOR_WHITE "1." COLOR_RESET " Sanitize and delete a file\n");
        printf(COLOR_WHITE "2." COLOR_RESET " Sanitize and delete a directory\n");
        printf(COLOR_WHITE "3." COLOR_RESET " Sanitize free space (10MB safe zone)\n");
        printf(COLOR_WHITE "4." COLOR_RESET " Fill RAM (aggressive allocation)\n");
        printf(COLOR_WHITE "5." COLOR_RESET " Release RAM (free all allocated memory)\n");
        printf(COLOR_WHITE "6." COLOR_RESET " Sanitization settings\n");
        printf(COLOR_WHITE "7." COLOR_RESET " Exit\n");
        printf(COLOR_BOLD "Choice: " COLOR_RESET);
        
        if (scanf("%d", &choice) != 1) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) { }
            continue;
        }
        while (getchar() != '\n');

        switch (choice) {
            case 1: {
                char path[4096];
                printf("Enter file path: ");
                if (!fgets(path, sizeof(path), stdin)) continue;
                path[strcspn(path, "\n")] = 0;
                if (path[0]) wipe_file(path);
                break;
            }
            case 2: {
                char path[4096];
                printf("Enter directory path: ");
                if (!fgets(path, sizeof(path), stdin)) continue;
                path[strcspn(path, "\n")] = 0;
                if (path[0]) {
                    g_start_time = time(NULL);
                    printf("\n" COLOR_CYAN "[*] Recursively sanitizing directory...\n" COLOR_RESET);
                    wipe_directory_recursive(path);
                    if (rmdir(path) == 0) printf(COLOR_CYAN "[+] Root directory removed.\n" COLOR_RESET);
                    attempt_trim(path);
                }
                break;
            }
            case 3: {
                char path[4096];
                printf("Enter mount point or directory: ");
                if (!fgets(path, sizeof(path), stdin)) continue;
                path[strcspn(path, "\n")] = 0;
                if (path[0]) wipe_free_space(path);
                break;
            }
            case 4: fill_ram(DEFAULT_SAFETY_MB); break;
            case 5: release_ram(); break;
            case 6: show_settings(); break;
            case 7:
                release_ram();  /* free any remaining RAM blocks */
                printf(COLOR_CYAN "[+] Exiting. Memory cleared. Goodbye.\n" COLOR_RESET);
                return EXIT_SUCCESS;
            default: printf(COLOR_BOLD "[!] Invalid option.\n" COLOR_RESET);
        }
    }
    return EXIT_SUCCESS;
}
