/*
 * claudeguard-helper — Privileged LaunchDaemon helper for ClaudeGuard (macOS).
 *
 * Security model:
 * 1. Invoked as root by launchd via /Library/LaunchDaemons/com.claudeguard.helper.plist
 *    watching <user_config_dir>/pending/request (no sudoers, no setuid binary).
 * 2. Determines the sole trusted UID from stat(<user_config_dir>).
 * 3. Opens staged files with O_RDONLY | O_NOFOLLOW and fstat()s the descriptor
 *    to prevent symlink / TOCTOU race attacks.
 * 4. Validates EVERY staged domain line and IP/CIDR token in C before touching
 *    /etc/hosts or synthesizing the pf anchor ruleset — user space can never
 *    inject arbitrary /etc/hosts overrides (e.g. localhost) or arbitrary pf syntax.
 * 5. Operates exclusively on macOS's sub-anchor "com.apple/claudeguard" with
 *    reference-counted pfctl -E / -X tokens and targeted per-CIDR state killing,
 *    preserving AirDrop, macOS Application Firewall, and V2rayN proxy tunnels.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_STAGED_HOSTS_BYTES (512 * 1024)
#define MAX_STAGED_PF_BYTES    (64 * 1024)
#define MAX_PF_ENTRIES         256

#define BLOCK_BEGIN  "# BEGIN CLAUDEGUARD BLOCKS"
#define BLOCK_END    "# END CLAUDEGUARD BLOCKS"
#define UPDATE_BEGIN "# BEGIN CLAUDEGUARD UPDATE BLOCKS"
#define UPDATE_END   "# END CLAUDEGUARD UPDATE BLOCKS"

#define SYS_SUPPORT_DIR "/Library/Application Support/ClaudeGuard"
#define VERIFIED_PF_FILE "/Library/Application Support/ClaudeGuard/pf.anchor.verified"
#define PF_TOKEN_FILE    "/Library/Application Support/ClaudeGuard/pf.token"
#define PF_ANCHOR_NAME   "com.apple/claudeguard"

static int open_trusted_file(const char *path, uid_t expected_uid, off_t max_bytes, size_t *out_size) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != expected_uid || st.st_size < 0 || st.st_size > max_bytes) {
        close(fd);
        return -1;
    }
    if (out_size) {
        *out_size = (size_t)st.st_size;
    }
    return fd;
}

static char *read_fd_all(int fd, size_t expected_size) {
    char *buf = (char *)calloc(expected_size + 1, 1);
    if (!buf) {
        return NULL;
    }
    size_t total = 0;
    while (total < expected_size) {
        ssize_t n = read(fd, buf + total, expected_size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            return NULL;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    return buf;
}

static int is_valid_domain(const char *domain) {
    size_t len = strlen(domain);
    if (len < 3 || len > 253) return 0;
    if (strcasecmp(domain, "localhost") == 0 ||
        strcasecmp(domain, "localhost.localdomain") == 0 ||
        strcasecmp(domain, "broadcasthost") == 0) {
        return 0;
    }
    if (domain[0] == '.' || domain[0] == '-' || domain[len - 1] == '.' || domain[len - 1] == '-') {
        return 0;
    }
    int has_dot = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)domain[i];
        if (c == '.') {
            has_dot = 1;
            if (i > 0 && domain[i - 1] == '.') return 0;
        } else if (!isalnum(c) && c != '-') {
            return 0;
        }
    }
    return has_dot;
}

static int is_valid_staged_hosts_line(const char *line) {
    if (line[0] == '\0') return 1;
    if (strcmp(line, BLOCK_BEGIN) == 0 ||
        strcmp(line, BLOCK_END) == 0 ||
        strcmp(line, UPDATE_BEGIN) == 0 ||
        strcmp(line, UPDATE_END) == 0) {
        return 1;
    }

    char ip_buf[64];
    char dom_buf[260];
    char extra[8];
    int matched = sscanf(line, "%63s %259s %7s", ip_buf, dom_buf, extra);
    if (matched != 2) {
        return 0;
    }
    if (strcmp(ip_buf, "0.0.0.0") != 0 &&
        strcmp(ip_buf, "127.0.0.1") != 0 &&
        strcmp(ip_buf, "::1") != 0) {
        return 0;
    }
    return is_valid_domain(dom_buf);
}

static int validate_staged_hosts_block(const char *content) {
    if (!content || content[0] == '\0') return 1;
    char *copy = strdup(content);
    if (!copy) return 0;

    char *cursor = copy;
    char *line = NULL;
    int valid = 1;
    while ((line = strsep(&cursor, "\n")) != NULL) {
        size_t l = strlen(line);
        if (l > 0 && line[l - 1] == '\r') line[l - 1] = '\0';
        if (!is_valid_staged_hosts_line(line)) {
            valid = 0;
            break;
        }
    }
    free(copy);
    return valid;
}

static int is_valid_ip_or_cidr(const char *token, int *is_ipv6_out) {
    if (!token || token[0] == '\0' || strlen(token) > 64) return 0;
    char buf[68];
    strncpy(buf, token, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        char *endptr = NULL;
        long val = strtol(slash + 1, &endptr, 10);
        if (!slash[1] || (endptr && *endptr != '\0') || val < 0 || val > 128) {
            return 0;
        }
        prefix = (int)val;
    }

    struct in_addr v4;
    if (inet_pton(AF_INET, buf, &v4) == 1) {
        if (prefix != -1 && (prefix < 1 || prefix > 32)) return 0; /* disallow /0 whole-internet block */
        if (ntohl(v4.s_addr) == INADDR_LOOPBACK || ntohl(v4.s_addr) == INADDR_ANY) return 0;
        if (is_ipv6_out) *is_ipv6_out = 0;
        return 1;
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, buf, &v6) == 1) {
        if (prefix != -1 && (prefix < 1 || prefix > 128)) return 0;
        if (IN6_IS_ADDR_LOOPBACK(&v6) || IN6_IS_ADDR_UNSPECIFIED(&v6)) return 0;
        if (is_ipv6_out) *is_ipv6_out = 1;
        return 1;
    }
    return 0;
}

static int merge_hosts_file(const char *hosts_in_path, const char *hosts_out_path, const char *staged_block) {
    int in_fd = open(hosts_in_path, O_RDONLY);
    if (in_fd < 0) return -1;
    struct stat st;
    if (fstat(in_fd, &st) != 0 || st.st_size < 0 || st.st_size > 4 * 1024 * 1024) {
        close(in_fd);
        return -1;
    }
    char *orig = read_fd_all(in_fd, (size_t)st.st_size);
    close(in_fd);
    if (!orig) return -1;

    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s.claudeguard.tmp", hosts_out_path);
    int out_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        free(orig);
        return -1;
    }
    (void)fchmod(out_fd, 0644);
    FILE *out_fp = fdopen(out_fd, "w");
    if (!out_fp) {
        close(out_fd);
        free(orig);
        return -1;
    }

    int inside_managed = 0;
    int trailing_blank_lines = 0;
    char *cursor = orig;
    char *line = NULL;
    while ((line = strsep(&cursor, "\n")) != NULL) {
        /* Skip final empty token after trailing newline */
        if (cursor == NULL && line[0] == '\0') break;

        if (strncmp(line, BLOCK_BEGIN, strlen(BLOCK_BEGIN)) == 0 ||
            strncmp(line, UPDATE_BEGIN, strlen(UPDATE_BEGIN)) == 0) {
            inside_managed = 1;
            continue;
        }
        if (inside_managed) {
            if (strncmp(line, BLOCK_END, strlen(BLOCK_END)) == 0 ||
                strncmp(line, UPDATE_END, strlen(UPDATE_END)) == 0) {
                inside_managed = 0;
            }
            continue;
        }

        if (line[0] == '\0') {
            trailing_blank_lines++;
            if (trailing_blank_lines <= 1) {
                fprintf(out_fp, "\n");
            }
        } else {
            trailing_blank_lines = 0;
            fprintf(out_fp, "%s\n", line);
        }
    }

    if (staged_block && staged_block[0] != '\0') {
        if (trailing_blank_lines == 0) {
            fprintf(out_fp, "\n");
        }
        fprintf(out_fp, "%s", staged_block);
        size_t slen = strlen(staged_block);
        if (staged_block[slen - 1] != '\n') {
            fprintf(out_fp, "\n");
        }
    }

    fflush(out_fp);
    fsync(fileno(out_fp));
    fclose(out_fp);
    free(orig);

    if (rename(tmp_path, hosts_out_path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

static int run_cmd(char *const argv[], char *stderr_buf, size_t stderr_cap) {
    int pipefd[2] = {-1, -1};
    if (stderr_buf && stderr_cap > 0) {
        if (pipe(pipefd) != 0) {
            pipefd[0] = pipefd[1] = -1;
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (pipefd[0] >= 0) { close(pipefd[0]); close(pipefd[1]); }
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            if (pipefd[1] < 0) dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        if (pipefd[1] >= 0) {
            close(pipefd[0]);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);
        }
        execv(argv[0], argv);
        _exit(127);
    }

    if (pipefd[1] >= 0) {
        close(pipefd[1]);
        size_t total = 0;
        while (total + 1 < stderr_cap) {
            ssize_t n = read(pipefd[0], stderr_buf + total, stderr_cap - 1 - total);
            if (n <= 0) break;
            total += (size_t)n;
        }
        stderr_buf[total] = '\0';
        close(pipefd[0]);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void flush_dns_cache(void) {
    char *ds_argv[] = {"/usr/bin/dscacheutil", "-flushcache", NULL};
    (void)run_cmd(ds_argv, NULL, 0);

    char *mdns_argv[] = {"/usr/bin/killall", "-HUP", "mDNSResponder", NULL};
    (void)run_cmd(mdns_argv, NULL, 0);
}

static void apply_pf_anchor(const char *pf_staged_text, int dry_run, const char *dry_pf_out_path) {
    char entries[MAX_PF_ENTRIES][68];
    int entry_is_v6[MAX_PF_ENTRIES];
    int count = 0;

    if (pf_staged_text && pf_staged_text[0] != '\0') {
        char *copy = strdup(pf_staged_text);
        if (copy) {
            char *cursor = copy;
            char *line = NULL;
            while ((line = strsep(&cursor, "\n")) != NULL && count < MAX_PF_ENTRIES) {
                while (*line && isspace((unsigned char)*line)) line++;
                size_t l = strlen(line);
                while (l > 0 && isspace((unsigned char)line[l - 1])) line[--l] = '\0';
                if (l == 0 || line[0] == '#') continue;

                int is_v6 = 0;
                if (is_valid_ip_or_cidr(line, &is_v6)) {
                    strncpy(entries[count], line, sizeof(entries[count]) - 1);
                    entries[count][sizeof(entries[count]) - 1] = '\0';
                    entry_is_v6[count] = is_v6;
                    count++;
                }
            }
            free(copy);
        }
    }

    if (dry_run) {
        if (dry_pf_out_path) {
            if (count == 0) {
                unlink(dry_pf_out_path);
            } else {
                FILE *fp = fopen(dry_pf_out_path, "w");
                if (fp) {
                    fprintf(fp, "table <claude_guard> persist {");
                    for (int i = 0; i < count; i++) fprintf(fp, " %s", entries[i]);
                    fprintf(fp, " }\nblock drop out quick proto { tcp, udp } to <claude_guard>\n");
                    fclose(fp);
                }
            }
        }
        return;
    }

    (void)mkdir(SYS_SUPPORT_DIR, 0755);

    if (count > 0) {
        int fd = open(VERIFIED_PF_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) return;
        FILE *fp = fdopen(fd, "w");
        if (!fp) {
            close(fd);
            return;
        }
        fprintf(fp, "table <claude_guard> persist {");
        for (int i = 0; i < count; i++) {
            fprintf(fp, " %s", entries[i]);
        }
        fprintf(fp, " }\nblock drop out quick proto { tcp, udp } to <claude_guard>\n");
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);

        /* Load into com.apple/claudeguard sub-anchor (evaluated by macOS's built-in com.apple wildcard) */
        char *load_argv[] = {"/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-f", VERIFIED_PF_FILE, NULL};
        (void)run_cmd(load_argv, NULL, 0);
        unlink(VERIFIED_PF_FILE);

        /* Acquire reference-counted PF enable token if we don't already hold one */
        if (access(PF_TOKEN_FILE, F_OK) != 0) {
            char err_buf[1024] = {0};
            char *en_argv[] = {"/sbin/pfctl", "-E", NULL};
            (void)run_cmd(en_argv, err_buf, sizeof(err_buf));
            char *tok_pos = strstr(err_buf, "Token : ");
            if (tok_pos) {
                tok_pos += strlen("Token : ");
                char token[64] = {0};
                int ti = 0;
                while (tok_pos[ti] && isdigit((unsigned char)tok_pos[ti]) && ti < 60) {
                    token[ti] = tok_pos[ti];
                    ti++;
                }
                token[ti] = '\0';
                if (ti > 0) {
                    int tfd = open(PF_TOKEN_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                    if (tfd >= 0) {
                        (void)write(tfd, token, (size_t)ti);
                        close(tfd);
                    }
                }
            }
        }

        /* Sever established TCP / UDP QUIC states ONLY to blocked targets (never kills V2rayN tunnel!) */
        for (int i = 0; i < count; i++) {
            const char *any_src = entry_is_v6[i] ? "::/0" : "0.0.0.0/0";
            char *kill_argv[] = {"/sbin/pfctl", "-k", (char *)any_src, "-k", entries[i], NULL};
            (void)run_cmd(kill_argv, NULL, 0);
        }
    } else {
        /* Flush ONLY our sub-anchor and release our PF token */
        char *flush_argv[] = {"/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-F", "all", NULL};
        (void)run_cmd(flush_argv, NULL, 0);

        int tfd = open(PF_TOKEN_FILE, O_RDONLY);
        if (tfd >= 0) {
            char token[64] = {0};
            ssize_t n = read(tfd, token, sizeof(token) - 1);
            close(tfd);
            if (n > 0) {
                token[n] = '\0';
                for (ssize_t k = 0; k < n; k++) {
                    if (!isdigit((unsigned char)token[k])) { token[k] = '\0'; break; }
                }
                if (token[0] != '\0') {
                    char *rel_argv[] = {"/sbin/pfctl", "-X", token, NULL};
                    (void)run_cmd(rel_argv, NULL, 0);
                }
            }
            unlink(PF_TOKEN_FILE);
        }
    }
}

int main(int argc, char *argv[]) {
    int dry_run = 0;
    const char *config_dir = NULL;
    const char *hosts_in = "/etc/hosts";
    const char *hosts_out = "/etc/hosts";
    const char *dry_pf_out = NULL;

    if (argc == 2) {
        config_dir = argv[1];
    } else if (argc >= 5 && strcmp(argv[1], "--verify-only") == 0) {
        dry_run = 1;
        config_dir = argv[2];
        hosts_in = argv[3];
        hosts_out = argv[4];
        if (argc >= 6) dry_pf_out = argv[5];
    } else {
        fprintf(stderr, "Usage: claudeguard-helper <config_dir>\n");
        return 2;
    }

    struct stat cst;
    if (stat(config_dir, &cst) != 0 || !S_ISDIR(cst.st_mode)) {
        fprintf(stderr, "claudeguard-helper: invalid config_dir\n");
        return 1;
    }
    uid_t trusted_uid = cst.st_uid;

    char staged_hosts_path[PATH_MAX];
    char staged_pf_path[PATH_MAX];
    snprintf(staged_hosts_path, sizeof(staged_hosts_path), "%s/pending/hosts.block", config_dir);
    snprintf(staged_pf_path, sizeof(staged_pf_path), "%s/pending/pf.anchor", config_dir);

    char *hosts_block_text = NULL;
    struct stat lst;
    if (lstat(staged_hosts_path, &lst) == 0) {
        size_t sz = 0;
        int hfd = open_trusted_file(staged_hosts_path, trusted_uid, MAX_STAGED_HOSTS_BYTES, &sz);
        if (hfd < 0) {
            fprintf(stderr, "claudeguard-helper: rejected untrusted hosts.block\n");
            return 1;
        }
        hosts_block_text = read_fd_all(hfd, sz);
        close(hfd);
        if (!hosts_block_text || !validate_staged_hosts_block(hosts_block_text)) {
            fprintf(stderr, "claudeguard-helper: rejected malformed hosts.block content\n");
            free(hosts_block_text);
            return 1;
        }
    }

    if (merge_hosts_file(hosts_in, hosts_out, hosts_block_text) != 0) {
        fprintf(stderr, "claudeguard-helper: failed to update hosts file\n");
        free(hosts_block_text);
        return 1;
    }
    free(hosts_block_text);

    if (!dry_run) {
        flush_dns_cache();
    }

    char *pf_text = NULL;
    if (lstat(staged_pf_path, &lst) == 0) {
        size_t psz = 0;
        int pfd = open_trusted_file(staged_pf_path, trusted_uid, MAX_STAGED_PF_BYTES, &psz);
        if (pfd < 0) {
            fprintf(stderr, "claudeguard-helper: rejected untrusted pf.anchor\n");
            return 1;
        }
        pf_text = read_fd_all(pfd, psz);
        close(pfd);
    }

    apply_pf_anchor(pf_text, dry_run, dry_pf_out);
    free(pf_text);
    return 0;
}
